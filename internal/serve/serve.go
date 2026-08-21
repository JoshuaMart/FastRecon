// Package serve exposes the pipeline over HTTP, for the serverless function
// deployment.
//
// The handler runs synchronously and answers with the report. On most FaaS
// platforms the instance is frozen or reclaimed once the handler returns, so
// "accept, answer 202, finish in the background" loses runs intermittently:
// work that cannot fit in a function's timeout belongs in a job.
package serve

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/app"
	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

const (
	// maxBodyBytes bounds a request body. The document is a handful of fields;
	// anything larger is a mistake or an attempt to exhaust the instance.
	maxBodyBytes = 64 << 10
	// busyRetryAfter is what a caller is told to wait when a run holds the
	// instance.
	busyRetryAfter = 30 * time.Second
	// shutdownGrace bounds the drain of an in-flight run on SIGTERM.
	shutdownGrace = 30 * time.Second
)

// Runner is what the handler drives. It is an interface so the HTTP contract
// — auth, refusal, deadlines, error mapping — can be tested without a
// network.
type Runner interface {
	Run(ctx context.Context, cfg *config.Config) (*report.Report, error)
	Redactor() *secrets.Redactor
	Config() *config.Config
}

// Server answers run requests from one process.
type Server struct {
	app   Runner
	token string
	log   *slog.Logger

	// running serializes runs. The enumeration engine keeps per-source state
	// on globally shared instances — API keys and the per-run counters — so
	// two runs in one process would overwrite each other's keys and report
	// each other's statistics.
	running sync.Mutex
}

// New builds the server.
func New(a Runner, cfg *config.Config, log *slog.Logger) (*Server, error) {
	if a == nil || cfg == nil || log == nil {
		return nil, errors.New("serve: app, configuration and logger are required")
	}
	token := strings.TrimSpace(cfg.APIToken)
	if token == "" {
		// An open subdomain-enumeration endpoint is free reconnaissance for
		// whoever finds it, charged to this deployment's API quotas.
		return nil, errors.New("serve: --api-token is required; refusing to expose an unauthenticated endpoint")
	}
	// This deployment builds no sinks: the report is the response. A webhook
	// configured here passes validation at startup and then never fires, which
	// from the outside looks exactly like one that fires and is never
	// received — so it is called out rather than left to be discovered.
	if cfg.WebhookURL != "" {
		log.Warn("webhook-url is ignored in serve mode; the report is returned in the response", "url", cfg.WebhookURL)
	}
	return &Server{app: a, token: token, log: log}, nil
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", s.handleRun)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

// ListenAndServe runs until ctx ends, then drains the in-flight run.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
		// A slow client must not hold an instance open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down", "grace", shutdownGrace.String())
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// runRequest is what a caller may specify.
//
// It says what to scan, never how the deployment is wired. Credentials, the
// source selection and the webhook destination come from the function's
// environment: the engine holds credentials in process-global state, and a
// caller-supplied destination would make the function a request-forwarding
// gadget onto its own network.
type runRequest struct {
	Domain  string   `json:"domain"`
	Exclude []string `json:"exclude,omitempty"`
	Stages  string   `json:"stages,omitempty"`
	Ports   string   `json:"ports,omitempty"`
	Timeout string   `json:"timeout,omitempty"`
}

// errorResponse is what a caller gets instead of a report.
type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		s.log.Warn("request rejected", "reason", "bad token", "remote", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	req, err := decodeRequest(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	runCfg, err := s.runConfig(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	// Refused rather than queued: a queued request spends its own deadline
	// waiting and then reports a timeout that explains nothing.
	if !s.running.TryLock() {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(busyRetryAfter.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "a run is already in progress on this instance"})
		return
	}
	defer s.running.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), budget(runCfg))
	defer cancel()

	rep, err := s.app.Run(ctx, runCfg)
	if err != nil {
		// The same split the exit codes make: a transient failure is ours, a
		// configuration the stages reject is the caller's. Not every option
		// can be checked before a stage is built — a port expression is
		// parsed by the scanner — so this is where those surface.
		if errors.Is(err, app.ErrRuntime) {
			s.log.Error("run failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
			return
		}
		s.log.Warn("request rejected", "reason", "stage setup", "error", err)
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	data, err := rep.Render(report.FormatJSON)
	if err != nil {
		s.log.Error("render report", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not render the report"})
		return
	}
	// The same last line of defence the one-shot path applies.
	data = s.app.Redactor().RedactBytes(data)

	// A partial report is data, not an error: it says so itself, in
	// completed and truncated_by_timeout.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append(data, '\n')); err != nil {
		s.log.Warn("response not delivered", "error", err)
	}
}

// authorized compares the bearer token in constant time.
func (s *Server) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(s.token)) == 1
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (runRequest, error) {
	var req runRequest
	// The writer is what lets the server stop reading and close the
	// connection when a body runs past the limit, instead of draining it.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	// An unknown field is a caller believing they configured something. Most
	// of them name an option that is deliberately not caller-settable, and
	// silently ignoring it would run a scan they did not ask for.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return runRequest{}, fmt.Errorf("invalid request body: %w", err)
	}
	return req, nil
}

// runConfig overlays the request onto the process configuration and validates
// the result with the same rules the command line uses.
func (s *Server) runConfig(req runRequest) (*config.Config, error) {
	cfg := s.app.Config().Clone()

	cfg.Domain = req.Domain
	if len(req.Exclude) > 0 {
		cfg.Exclude = req.Exclude
	}
	if req.Ports != "" {
		cfg.Ports = req.Ports
	}
	if req.Stages != "" {
		scope, err := stage.ParseScope(req.Stages)
		if err != nil {
			return nil, err
		}
		cfg.Scope = scope
	}
	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout %q: %w", req.Timeout, err)
		}
		cfg.Timeout = d
	}

	// The exclusion file was merged at startup; a request cannot name one.
	cfg.ExcludeFile = ""
	// The report is the response. Sinks belong to the deployment.
	cfg.Output = config.StdoutPath

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// budget reserves the output margin so the caller receives a well-formed
// truncated report rather than a platform-level timeout.
func budget(cfg *config.Config) time.Duration {
	reserved := time.Duration(float64(cfg.Timeout) * cfg.OutputMargin)
	if d := cfg.Timeout - reserved; d > 0 {
		return d
	}
	return cfg.Timeout
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

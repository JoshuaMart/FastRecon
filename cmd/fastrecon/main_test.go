package main

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/logging"
)

// quiet runs fn with stdout discarded. The subcommands under test print for a
// living, and their output is not what is being asserted.
func quiet(t *testing.T, fn func() int) int {
	t.Helper()
	saved := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devNull
	defer func() {
		os.Stdout = saved
		_ = devNull.Close()
	}()
	return fn()
}

// A scheduler keys its retry on the exit status, so these are a contract and
// not an implementation detail. Every case here must decide before any stage
// runs: none of them may reach the network.
func TestDispatchExitCodes(t *testing.T) {
	cases := map[string]struct {
		args []string
		want int
	}{
		"version":               {[]string{"version"}, exitOK},
		"sources":               {[]string{"sources"}, exitOK},
		"help":                  {[]string{"help"}, exitOK},
		"unknown flag":          {[]string{"--no-such-flag"}, exitUsage},
		"unexpected argument":   {[]string{"example.com"}, exitUsage},
		"missing domain":        {[]string{"run"}, exitUsage},
		"domain is a url":       {[]string{"-d", "https://example.com"}, exitUsage},
		"unknown scope":         {[]string{"-d", "example.com", "--stages", "everything"}, exitUsage},
		"unknown format":        {[]string{"-d", "example.com", "--format", "yaml"}, exitUsage},
		"no destination":        {[]string{"-d", "example.com", "--output", ""}, exitUsage},
		"serve without a token": {[]string{"serve"}, exitUsage},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := quiet(t, func() int { return dispatch(tc.args) }); got != tc.want {
				t.Errorf("dispatch(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

// `run` is the default: the subcommand is optional and must not change the
// meaning of what follows it.
func TestRunSubcommandIsOptional(t *testing.T) {
	withPrefix := quiet(t, func() int { return dispatch([]string{"run", "--stages", "everything", "-d", "example.com"}) })
	without := quiet(t, func() int { return dispatch([]string{"--stages", "everything", "-d", "example.com"}) })
	if withPrefix != without {
		t.Errorf("dispatch with 'run' = %d, without = %d: the prefix must be transparent", withPrefix, without)
	}
}

// The delivery budget is what keeps a report from dying with the run that
// produced it: the deadline is reached, the stages stop, and the report still
// has time to reach its destinations.
func TestDeliveryContextReservesTheOutputMargin(t *testing.T) {
	ctx, cancel := deliveryContext(&config.Config{Timeout: 100 * time.Second, OutputMargin: 0.1})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("the delivery context must carry a deadline")
	}
	if left := time.Until(deadline); left < 9*time.Second || left > 11*time.Second {
		t.Errorf("budget = %s, want about 10s (10%% of 100s)", left)
	}
}

// A configuration with no usable margin must still leave time to deliver,
// rather than cancelling the write immediately.
func TestDeliveryContextFallsBackWhenTheMarginIsZero(t *testing.T) {
	ctx, cancel := deliveryContext(&config.Config{})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("the delivery context must carry a deadline")
	}
	if left := time.Until(deadline); left < 29*time.Second {
		t.Errorf("budget = %s, want the 30s fallback", left)
	}
}

// The delivery context must survive the signal that ended the run, or a
// cancelled run would produce a partial report and then drop it.
func TestDeliveryContextOutlivesTheRun(t *testing.T) {
	ctx, cancel := deliveryContext(&config.Config{Timeout: time.Minute, OutputMargin: 0.5})
	defer cancel()

	if err := ctx.Err(); err != nil {
		t.Errorf("the delivery context starts cancelled: %v", err)
	}
}

func TestBuildSinks(t *testing.T) {
	log := logging.Discard()

	cases := map[string]struct {
		cfg  *config.Config
		want []string
	}{
		"stdout by default": {
			&config.Config{Output: config.StdoutPath},
			[]string{"stdout"},
		},
		"a path selects the file sink": {
			&config.Config{Output: "/tmp/report.json"},
			[]string{"file"},
		},
		"a webhook is additive": {
			&config.Config{Output: config.StdoutPath, WebhookURL: "https://example.com/hook", WebhookMethod: "POST", WebhookTimeout: time.Second},
			[]string{"stdout", "webhook"},
		},
		"file and webhook together": {
			&config.Config{Output: "/tmp/report.json", WebhookURL: "https://example.com/hook", WebhookMethod: "POST", WebhookTimeout: time.Second},
			[]string{"file", "webhook"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sinks, err := buildSinks(tc.cfg, log)
			if err != nil {
				t.Fatalf("buildSinks: %v", err)
			}
			var got []string
			for _, s := range sinks {
				got = append(got, s.Name())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("sinks = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildSinksRejectsAnUnusableWebhook(t *testing.T) {
	_, err := buildSinks(&config.Config{
		Output:         config.StdoutPath,
		WebhookURL:     "https://example.com/hook",
		WebhookMethod:  "POST",
		WebhookTimeout: time.Second,
		WebhookHeaders: []string{"NoColonHere"},
	}, logging.Discard())
	if err == nil {
		t.Error("buildSinks accepted a malformed webhook header")
	}
}

// Header values carry bearer tokens, so only the names may be logged.
func TestHeaderNamesDropTheValues(t *testing.T) {
	got := headerNames([]string{"Authorization: Bearer super-secret", "X-Trace : 42", "Malformed"})
	want := []string{"Authorization", "X-Trace", "Malformed"}
	if !slices.Equal(got, want) {
		t.Fatalf("headerNames = %v, want %v", got, want)
	}
	for _, name := range got {
		if name == "Bearer super-secret" {
			t.Error("a header value reached the log")
		}
	}
}

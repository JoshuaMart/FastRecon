package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

type HttpxResponse struct {
	URL     string            `json:"url"`
	Status  int               `json:"status_code"`
	Size    int               `json:"content_length"`
	Type    string            `json:"content_type"`
	Title   string            `json:"title"`
	IP      []string          `json:"a"`
	CNAME   []string          `json:"cname"`
	CDN     bool              `json:"cdn"`
	Tech    []string          `json:"tech"`
	Headers map[string]string `json:"header"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	domain := r.URL.Query().Get("domain")
	rawParam := r.URL.Query().Get("raw")

	if domain == "" {
		http.Error(w, "Error: domain parameter is required", http.StatusBadRequest)
		return
	}

	// Build httpx command based on raw parameter
	var httpxCmd string
	if rawParam == "true" {
		httpxCmd = "httpx -silent"
	} else {
		httpxCmd = "httpx -silent -sc -cl -ct -title -td -ip -cname -cdn -irh -j"
	}

	// Run the command and capture the output
	var output bytes.Buffer
	command := fmt.Sprintf(`subfinder -pc subfinder.yaml -silent -d %s |
	                        puredns resolve -q --resolvers resolvers.txt --resolvers-trusted resolvers-trusted.txt |
	                        %s
                           `, domain, httpxCmd)

	exec := exec.Command("sh", "-c", command)
	exec.Stdout = &output
	err := exec.Run()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	// If raw=true, return the domain list directly
	if rawParam == "true" {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(output.Bytes())
		return
	}

	// Otherwise, parse JSON as before
	scanner := bufio.NewScanner(strings.NewReader(output.String()))
	var jsonArray []HttpxResponse

	for scanner.Scan() {
		line := scanner.Text()
		var httpxResponse HttpxResponse

		err := json.Unmarshal([]byte(line), &httpxResponse)
		if err != nil {
			fmt.Fprintf(w, "Error parsing JSON Lines output: %v", err)
			return
		}
		jsonArray = append(jsonArray, httpxResponse)
	}

	// Convert the slice of JSON objects to a single JSON array
	jsonBytes, err := json.Marshal(jsonArray)
	if err != nil {
		fmt.Fprintf(w, "Error converting JSON array to bytes: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
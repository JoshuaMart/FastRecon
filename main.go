package main

import (
	"encoding/json"
	"fmt"
	"bytes"
	"net/http"
	"bufio"
	"strings"
	"os/exec"
)

type HttpxResponse struct {
	URL     string                 `json:"url"`
	Status  int                    `json:"status_code"`
	Size	int                    `json:"content_length"`
	Type	string                 `json:"content_type"`
	Title   string                 `json:"title"`
	IP      []string               `json:"a"`
	CNAME   []string               `json:"cname"`
	CDN     bool                   `json:"cdn"`
	Tech    []string               `json:"tech"`
	Headers map[string]string      `json:"header"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/")
	if domain == "" {
		http.Error(w, "Error: domain is required", http.StatusBadRequest)
		return
	}

	// Run the command and capture the output
	var output bytes.Buffer
	command := fmt.Sprintf(`subfinder -pc subfinder.yaml -silent -d %s |
	                        puredns resolve -q --resolvers resolvers.txt --resolvers-trusted resolvers-trusted.txt |
	                        httpx -silent -sc -cl -ct -title -td -ip -cname -cdn -irh -j
                           `, domain)

	exec := exec.Command("sh", "-c", command)
	exec.Stdout = &output
	err := exec.Run()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	// Read the output line by line
	scanner := bufio.NewScanner(strings.NewReader(output.String()))

	// Parse the JSON Lines output
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
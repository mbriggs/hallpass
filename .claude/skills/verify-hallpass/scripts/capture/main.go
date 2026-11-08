// capture sits between gh and a scratch broker's gh socket. It logs each
// request, and the broker's verdict, as one JSONL record:
//
//	{"head": "POST /graphql HTTP/1.1\r\n...", "body": "...", "status": 403, "refusal": "hallpass: ..."}
//
// head and body match internal/policy/testdata's corpus format. A line
// {"mark": "..."} that gh-matrix.sh writes between commands names the
// command the following records came from.
//
//	capture -listen SOCK -broker GH_SOCK -out FILE
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

func main() {
	listen := flag.String("listen", "", "socket for gh's http_unix_socket")
	broker := flag.String("broker", "", "the scratch broker's gh.sock")
	out := flag.String("out", "", "JSONL file to append to")
	flag.Parse()
	if *listen == "" || *broker == "" || *out == "" {
		log.Fatal("capture: -listen, -broker, and -out are required")
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *broker)
		},
	}}
	var mu sync.Mutex
	refusal := regexp.MustCompile(`hallpass: [^"]*`)

	os.Remove(*listen)
	ln, err := net.Listen("unix", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
		req.Header = r.Header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		rec := map[string]any{"head": head(r), "body": string(body), "status": resp.StatusCode}
		if m := refusal.Find(respBody); m != nil {
			rec["refusal"] = string(m)
		}
		b, _ := json.Marshal(rec)
		mu.Lock()
		f.Write(append(b, '\n'))
		mu.Unlock()

		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	})))
}

// head rebuilds the request line and headers, sorted, with the token
// replaced, as the corpus stores them.
func head(r *http.Request) string {
	lines := []string{r.Method + " " + r.URL.RequestURI() + " HTTP/1.1", "Host: " + r.Host}
	var keys []string
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.Join(r.Header[k], ", ")
		if k == "Authorization" {
			v = "token hallpass-dummy"
		}
		lines = append(lines, k+": "+v)
	}
	return strings.Join(lines, "\r\n")
}

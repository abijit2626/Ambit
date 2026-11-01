// fake-http-mcp is the smoke test's MCP server over Streamable HTTP. It serves the same tools and the same
// answers, byte for byte, as the stdio fake server in interpose-smoke.sh, so the two client streams can be
// compared. It writes the address it listens on to -ready, and one line per request to -log naming what
// it saw: whether Authorization matched -want-auth, and the session id it was sent.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

const (
	initResult = `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"wiki","version":"3.2.0"}}}`
	listResult = `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"search","description":"Search the wiki","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}},"annotations":{"readOnlyHint":true}},{"name":"publish","description":"Publish a page to the wiki","inputSchema":{"type":"object"}}]}}`
	callResult = `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done"}]}}`
	sessionID  = "smoke-session"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	ready := flag.String("ready", "", "file to write the listening address to")
	logPath := flag.String("log", "", "file to write one line per request to")
	wantAuth := flag.String("want-auth", "", "the Authorization value every request must carry")
	flag.Parse()

	var mu sync.Mutex
	var reqLog *os.File
	if *logPath != "" {
		f, err := os.Create(*logPath)
		if err != nil {
			log.Fatal(err)
		}
		reqLog = f
	}
	note := func(format string, a ...any) {
		if reqLog == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(reqLog, format+"\n", a...)
	}

	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		auth := "auth=ok"
		if r.Header.Get("Authorization") != *wantAuth {
			auth = "auth=wrong"
		}
		note("%s %s session=%q", r.Method, auth, r.Header.Get("Mcp-Session-Id"))
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			return
		case http.MethodGet:
			http.Error(w, "no server stream", http.StatusMethodNotAllowed)
			return
		case http.MethodPost:
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", sessionID)
			fmt.Fprintf(w, initResult, m.ID)
		case "tools/list":
			fmt.Fprintf(w, listResult, m.ID)
		case "tools/call":
			fmt.Fprintf(w, callResult, m.ID)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, m.ID)
		}
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if *ready != "" {
		if err := os.WriteFile(*ready, []byte(ln.Addr().String()), 0o600); err != nil {
			log.Fatal(err)
		}
	}
	log.Fatal(http.Serve(ln, nil))
}

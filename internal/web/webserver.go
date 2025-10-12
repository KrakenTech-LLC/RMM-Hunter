package web

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/hunter"

	"github.com/gorilla/websocket"
)

//go:embed templates/*
var contentFS embed.FS

// broadcaster for hunt logs
type wsHub struct {
	mu    sync.Mutex
	conns map[*websocket.Conn]struct{}
}

func newHub() *wsHub                   { return &wsHub{conns: make(map[*websocket.Conn]struct{})} }
func (h *wsHub) add(c *websocket.Conn) { h.mu.Lock(); h.conns[c] = struct{}{}; h.mu.Unlock() }
func (h *wsHub) rm(c *websocket.Conn)  { h.mu.Lock(); delete(h.conns, c); h.mu.Unlock() }
func (h *wsHub) send(msg string) {
	h.mu.Lock()
	for c := range h.conns {
		_ = c.WriteMessage(websocket.TextMessage, []byte(msg))
	}
	h.mu.Unlock()
}

// JSONReportMeta is a lightweight descriptor for previous hunts
type JSONReportMeta struct {
	File        string `json:"file"`
	ReportName  string `json:"reportName"`
	GeneratedAt string `json:"generatedAt"`
}

type server struct {
	hub    *wsHub
	http   *http.Server
	quitCh chan struct{}
}

func StartWebServer() {
	h := newHub()
	s := &server{hub: h, quitCh: make(chan struct{})}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/logo", s.handleLogo)
	mux.HandleFunc("/api/hunts", s.handleListHunts)
	mux.HandleFunc("/api/hunt/start", s.handleStartHunt)
	mux.HandleFunc("/api/report", s.handleGetReport)
	mux.HandleFunc("/api/quit", s.handleQuit)
	mux.HandleFunc("/ws/hunt", s.handleWS)

	s.http = &http.Server{Addr: ":8080", Handler: logRequests(mux)}
	go func() {
		log.Printf("[web] starting on http://127.0.0.1:8080\n")
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// block until quit
	<-s.quitCh
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
	os.Exit(0)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := contentFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "template missing", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// serve logo from repo .img; fallback to 404
func (s *server) handleLogo(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(".img", "rmm-hunter.png")
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "image/png")
	http.ServeContent(w, r, "rmm-hunter.png", time.Now(), f)
}

func (s *server) handleListHunts(w http.ResponseWriter, r *http.Request) {
	files, _ := filepath.Glob("*.json")
	var out []JSONReportMeta
	for _, f := range files {
		// read small head of file to verify
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var env struct {
			ReportName  string `json:"reportName"`
			GeneratedAt string `json:"generatedAt"`
		}
		if json.Unmarshal(b, &env) == nil && (env.ReportName != "" || strings.Contains(string(b), "\"findings\"")) {
			out = append(out, JSONReportMeta{File: f, ReportName: env.ReportName, GeneratedAt: env.GeneratedAt})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("file")
	if f == "" || strings.Contains(f, "..") {
		http.Error(w, "bad file", 400)
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *server) handleStartHunt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", 405)
		return
	}
	name := fmt.Sprintf("hunt-%s", time.Now().Format("20060102-150405"))
	go s.runHunt(name)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"reportName": name})
}

func (s *server) runHunt(name string) {
	// redirect stdout to our pipe
	oldStdout := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	// also mirror stderr
	oldStderr := os.Stderr
	pr2, pw2, _ := os.Pipe()
	os.Stderr = pw2

	// reader goroutines
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			s.hub.send(sc.Text())
		}
		done <- struct{}{}
	}()
	go func() {
		sc := bufio.NewScanner(pr2)
		for sc.Scan() {
			s.hub.send(sc.Text())
		}
		done <- struct{}{}
	}()

	// run hunter
	hunter.Start(pkg.RunOptions{Name: name})

	// close writers and restore
	_ = pw.Close()
	_ = pw2.Close()
	<-done
	<-done
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	s.hub.send("[+] Hunt complete")
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.hub.add(c)
	defer func() { s.hub.rm(c); _ = c.Close() }()
	for { // keep alive until client closes
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
	}
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
	go func() { time.Sleep(200 * time.Millisecond); s.quitCh <- struct{}{} }()
}

package solstice

import (
	"fmt"
	"log"
	"net/http"
	"spewwerrier/solstice/utils"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var BlockedIpaddrChan = make(chan []byte, 10)
var LogsIpaddrChan = make(chan []byte, 10)

type Server struct {
	mux *http.ServeMux
}

func (s *Server) setEndpoints() {
	s.mux.HandleFunc("/", indexHandler)
	s.mux.HandleFunc("/blockedip", sseHandlerBlocked)

	s.mux.HandleFunc("/logs", logsHandler)
	s.mux.HandleFunc("/logsip", sseHandlerLogs)

}

func (s *Server) Start() {
	s.mux = http.NewServeMux()
	s.setEndpoints()

	serv := &http.Server{
		Addr:    "localhost:3000",
		Handler: s.mux,
	}

	if err := serv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start:", err)
	}
}

func sseHandlerBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for ip := range BlockedIpaddrChan {
		fmt.Fprintf(w, "data: %s\n\n", utils.ParseIpAddr(ip))
		flusher.Flush()
		time.Sleep(1 * time.Second)
	}
}

func sseHandlerLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for ip := range LogsIpaddrChan {
		fmt.Fprintf(w, "data: %s\n\n", utils.ParseIpAddr(ip))
		flusher.Flush()
		time.Sleep(1 * time.Second)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>IP Logs</title>
	</head>
	<body>
		<h1>Blocked IP Logs</h1>
		<div id="log"></div>
		<script>
			const eventSource = new EventSource("/blockedip");
			eventSource.onmessage = function(event) {
				const logDiv = document.getElementById("log");
				const newEntry = document.createElement("p");
				newEntry.textContent = event.data;
				logDiv.prepend(newEntry);
			};
		</script>
	</body>
	</html>
	`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>IP Logs</title>
	</head>
	<body>
		<h1>Unblocked IP Logs</h1>
		<div id="log"></div>
		<script>
			const eventSource = new EventSource("/logsip");
			eventSource.onmessage = function(event) {
				const logDiv = document.getElementById("log");
				const newEntry = document.createElement("p");
				newEntry.textContent = event.data;
				logDiv.prepend(newEntry);
			};
		</script>
	</body>
	</html>
	
	`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

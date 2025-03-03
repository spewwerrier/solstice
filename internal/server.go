package solstice

import (
	"fmt"
	"log"
	"net/http"
	"spewwerrier/solstice/utils"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var BlockedIpaddrChan = make(chan []byte, 10)
var LogsIpaddrChan = make(chan []byte, 10)

type Server struct {
	mux  *http.ServeMux
	db   *Sequel
	objs *packetObjects
}

func (s *Server) setEndpoints() {
	s.mux.HandleFunc("/", indexHandler)
	s.mux.HandleFunc("/blockedip", sseHandlerBlocked)

	s.mux.HandleFunc("/logs", logsHandler)
	s.mux.HandleFunc("/logsip", sseHandlerLogs)

	s.mux.HandleFunc("/savefilter", s.saveFilter)
}

func (s *Server) Start(sqlite *Sequel, objs *packetObjects) {
	s.mux = http.NewServeMux()
	s.db = sqlite
	s.objs = objs

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

func (s *Server) saveFilter(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ipv4 := r.Form.Get("ipv4")
	if len(ipv4) > 0 {
		u32_ipv4, _ := strconv.ParseUint(ipv4, 10, 32)
		AppendIpv4(s.objs, uint32(u32_ipv4))
		s.db.DbAppendIpv4(uint32(u32_ipv4))
		w.Write([]byte("saved in db"))
		return
	}

	high := r.Form.Get("high")
	if len(high) > 0 {
		low := r.Form.Get("low")
		u64_high, _ := strconv.ParseUint(high, 10, 64)
		u64_low, _ := strconv.ParseUint(low, 10, 64)

		ipv6 := packetIpv6Addr{
			High: u64_high,
			Low:  u64_low,
		}

		AppendIpv6(s.objs, ipv6)
		s.db.DbAppendIpv6(ipv6)
		w.Write([]byte("saved in db"))
		return
	}

}

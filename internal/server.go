package solstice

import (
	"log"
	"net/http"
	solstice "spewwerrier/solstice/utils"
)

type Server struct {
	mux    *http.ServeMux
	Ipdata []byte
}

func (s *Server) LogsHomepage(w http.ResponseWriter) {
	w.Write([]byte("ok"))
	solstice.ParseIpAddr(s.Ipdata)
}

func (s *Server) setEndpoints() {
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.LogsHomepage(w)
		// w.Write([]byte("ok"))
	})

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

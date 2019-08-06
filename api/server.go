package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/mayuresh82/auto_remediation/models"
	"github.com/mayuresh82/auto_remediation/remediator"
)

type Server struct {
	addr string
	rem  *remediator.Remediator
}

func NewServer(addr string, rem *remediator.Remediator) *Server {
	return &Server{addr: addr, rem: rem}
}

func (s *Server) Start(ctx context.Context) {
	router := mux.NewRouter()
	router.HandleFunc("/api/{category}", s.Get).Methods("GET")
	//router.HandleFunc("/api/auth", s.AuthAlertManager).Methods("POST")
	//router.HandleFunc("/api/commands/run", s.RunCommand).Methods("POST")
	router.HandleFunc("/admin/{state}", s.SetState).Methods("POST")

	// set up the router
	srv := &http.Server{
		Handler: router,
		Addr:    s.addr,
		// set some sane timeouts
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}
	glog.Infof("Starting API server on %s", s.addr)
	srv.ListenAndServe()
}

func (s *Server) Get(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if vars["category"] == "rules" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.rem.Config.Rules)
		return
	}
	params := make(map[string]interface{})
	for q, v := range req.URL.Query() {
		if vars["category"] == "remediations" && q == "status" {
			if val, ok := models.StatusMap[v[0]]; ok {
				params[q] = val
				continue
			}
		}
		params[q] = v[0]
	}
	items, err := s.rem.Db.Query(vars["category"], params)
	if err != nil {
		glog.Errorf("Failed to query items: %v", err)
		http.Error(w, fmt.Sprintf("Failed to query items: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func (s *Server) SetState(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		http.Error(w, "Missing username/password", http.StatusBadRequest)
		return
	}
	adminUser, adminPass := s.rem.Config.AdminCreds()
	if user != adminUser && pass != adminPass {
		http.Error(w, "Authentication Failed", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(req)
	var err error
	switch vars["state"] {
	case "enable":
		err = s.rem.Enable()
	case "disable":
		err = s.rem.Disable()
	default:
		err = fmt.Errorf("Invalid request, choose either 'enable' or 'disable'")
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to disable: %v", err), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "System is now %sd\n", vars["state"])
}

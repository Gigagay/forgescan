package main

import (
	"log"
	"net/http"
	"time"

	"forgescan/scanner-runner/internal/api"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	r.Route("/run-scan", func(r chi.Router) {
		r.Post("/", api.RunScanHandler)
	})

	srv := &http.Server{
		Addr:         "127.0.0.1:9001",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Minute,
	}

	log.Println("Scanner runner listening on 127.0.0.1:9001")
	log.Fatal(srv.ListenAndServe())
}

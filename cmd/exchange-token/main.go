package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"z4ce.com/snyk-oidc-exchange/pkg/exchange"
)

func main() {
	allowedOwner := os.Getenv("ALLOWED_OWNER")
	if allowedOwner == "" {
		log.Fatal("ALLOWED_OWNER environment variable is required")
	}

	service, err := exchange.NewService(context.Background(), allowedOwner)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/exchange", service.ExchangeToken)

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

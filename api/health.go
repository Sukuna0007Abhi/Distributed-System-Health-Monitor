package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

func Health(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "health-monitor",
		"version":   "1.0.0",
		"message":   "🚀 Health Monitor with CoRIM Integration - Live Demo Ready!",
		"features": []string{
			"Enterprise-grade health monitoring",
			"CoRIM attestation integration", 
			"Real-time validation",
			"Resume-ready deployment",
		},
		"endpoints": map[string]string{
			"health":        "/health",
			"corim_profiles": "/api/v1/corim/profiles",
			"metrics":       "/metrics",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
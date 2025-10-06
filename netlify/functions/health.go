package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "health-monitor",
		"version":   "1.0.0",
		"message":   "🚀 Health Monitor with CoRIM Integration - Live on Netlify!",
		"platform":  "Netlify Serverless",
		"features": []string{
			"Enterprise-grade health monitoring",
			"CoRIM attestation integration",
			"Real-time validation",
			"Serverless architecture",
			"Resume-ready deployment",
		},
		"endpoints": map[string]string{
			"health":         "/health",
			"corim_profiles": "/api/v1/corim/profiles",
			"metrics":        "/metrics",
		},
		"demo_info": map[string]string{
			"github":     "https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor",
			"deployment": "Netlify Edge Functions",
			"resume_tip": "Add this live URL to your resume to showcase serverless expertise!",
		},
	}

	body, _ := json.Marshal(response)

	return &events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type",
		},
		Body: string(body),
	}, nil
}

func main() {
	lambda.Start(handler)
}
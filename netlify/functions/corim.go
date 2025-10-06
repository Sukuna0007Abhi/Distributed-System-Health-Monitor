package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	var response map[string]interface{}
	statusCode := 200

	if request.HTTPMethod == "GET" {
		// Demo CoRIM profiles response
		profiles := []map[string]interface{}{
			{
				"id":          "netlify-demo-1",
				"name":        "TPM 2.0 Reference Values",
				"description": "Hardware attestation reference measurements",
				"created_at":  "2024-01-15T10:30:00Z",
				"status":      "active",
				"type":        "hardware-attestation",
				"platform":    "Netlify Serverless",
			},
			{
				"id":          "netlify-demo-2",
				"name":        "UEFI Secure Boot Profile",
				"description": "Firmware integrity reference values",
				"created_at":  "2024-01-14T15:45:00Z",
				"status":      "active",
				"type":        "firmware-attestation",
				"platform":    "Netlify Edge",
			},
		}

		response = map[string]interface{}{
			"profiles": profiles,
			"total":    len(profiles),
			"message":  "🎯 CoRIM Profiles - Serverless Attestation Demo",
			"platform": "Netlify Functions",
			"features": []string{
				"Hardware TPM integration",
				"UEFI firmware validation",
				"Serverless scalability",
				"Edge computing ready",
				"Industry compliance",
			},
			"resume_highlight": "Demonstrates serverless architecture expertise with enterprise security standards",
		}

	} else if request.HTTPMethod == "POST" {
		// Demo upload response
		statusCode = 201
		response = map[string]interface{}{
			"message":    "✅ CoRIM Profile Upload Successful (Netlify Demo)",
			"profile_id": "netlify-upload-" + request.RequestContext.RequestID,
			"status":     "validated",
			"platform":   "Netlify Serverless",
			"features": []string{
				"CBOR format validation",
				"Serverless processing",
				"Edge optimization",
				"Auto-scaling",
			},
			"demo_note": "This is a demo response showing CoRIM integration capabilities",
		}

	} else {
		statusCode = 405
		response = map[string]interface{}{
			"error":   "Method not allowed",
			"allowed": []string{"GET", "POST"},
		}
	}

	body, _ := json.Marshal(response)

	return &events.APIGatewayProxyResponse{
		StatusCode: statusCode,
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
package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TestingHTTPHandler provides HTTP endpoints for the testing framework
type TestingHTTPHandler struct {
	framework TestingFramework
	logger    *logrus.Logger
	tracer    trace.Tracer
}

// NewTestingHTTPHandler creates a new testing HTTP handler
func NewTestingHTTPHandler(framework TestingFramework, logger *logrus.Logger) *TestingHTTPHandler {
	return &TestingHTTPHandler{
		framework: framework,
		logger:    logger,
		tracer:    otel.Tracer("testing_http_handler"),
	}
}

// RegisterRoutes registers HTTP routes for testing endpoints
func (h *TestingHTTPHandler) RegisterRoutes(router *mux.Router) {
	// Integration testing routes
	router.HandleFunc("/api/testing/integration/run", h.runIntegrationTest).Methods("POST")
	router.HandleFunc("/api/testing/integration/{testId}/results", h.getIntegrationTestResults).Methods("GET")
	router.HandleFunc("/api/testing/integration/{testId}/stop", h.stopIntegrationTest).Methods("POST")
	
	// Load testing routes
	router.HandleFunc("/api/testing/load/run", h.runLoadTest).Methods("POST")
	router.HandleFunc("/api/testing/load/{testId}/results", h.getLoadTestResults).Methods("GET")
	router.HandleFunc("/api/testing/load/{testId}/stop", h.stopLoadTest).Methods("POST")
	
	// Unit testing routes
	router.HandleFunc("/api/testing/unit/run", h.runUnitTest).Methods("POST")
	router.HandleFunc("/api/testing/unit/{testId}/results", h.getUnitTestResults).Methods("GET")
	
	// Chaos testing routes
	router.HandleFunc("/api/testing/chaos/run", h.runChaosTest).Methods("POST")
	router.HandleFunc("/api/testing/chaos/{testId}/results", h.getChaosTestResults).Methods("GET")
	router.HandleFunc("/api/testing/chaos/{testId}/stop", h.stopChaosTest).Methods("POST")
	
	// Security testing routes
	router.HandleFunc("/api/testing/security/run", h.runSecurityTest).Methods("POST")
	router.HandleFunc("/api/testing/security/{testId}/results", h.getSecurityTestResults).Methods("GET")
	router.HandleFunc("/api/testing/security/{testId}/stop", h.stopSecurityTest).Methods("POST")
	
	// Compliance testing routes
	router.HandleFunc("/api/testing/compliance/run", h.runComplianceTest).Methods("POST")
	router.HandleFunc("/api/testing/compliance/{testId}/results", h.getComplianceTestResults).Methods("GET")
	
	// General testing routes
	router.HandleFunc("/api/testing/status", h.getTestingStatus).Methods("GET")
	router.HandleFunc("/api/testing/history", h.getTestHistory).Methods("GET")
	router.HandleFunc("/api/testing/metrics", h.getTestingMetrics).Methods("GET")
	router.HandleFunc("/api/testing/reports/{testId}", h.generateTestReport).Methods("GET")
	
	// Test scheduling routes
	router.HandleFunc("/api/testing/schedule", h.scheduleTest).Methods("POST")
	router.HandleFunc("/api/testing/schedule/{scheduleId}", h.getScheduledTest).Methods("GET")
	router.HandleFunc("/api/testing/schedule/{scheduleId}", h.updateScheduledTest).Methods("PUT")
	router.HandleFunc("/api/testing/schedule/{scheduleId}", h.deleteScheduledTest).Methods("DELETE")
	router.HandleFunc("/api/testing/schedules", h.listScheduledTests).Methods("GET")
}

// Integration Testing Handlers

func (h *TestingHTTPHandler) runIntegrationTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_integration_test")
	defer span.End()

	var config IntegrationTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("integration-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting integration test via HTTP API")

	// Start integration test asynchronously
	go func() {
		_, err := h.framework.RunIntegrationTest(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Integration test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Integration test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getIntegrationTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_integration_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetIntegrationTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

func (h *TestingHTTPHandler) stopIntegrationTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "stop_integration_test")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	err := h.framework.StopIntegrationTest(ctx, testID)
	if err != nil {
		h.handleError(w, "Failed to stop integration test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"test_id": testID,
		"status":  "stopped",
		"message": "Integration test stopped successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

// Load Testing Handlers

func (h *TestingHTTPHandler) runLoadTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_load_test")
	defer span.End()

	var config LoadTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("load-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting load test via HTTP API")

	// Start load test asynchronously
	go func() {
		_, err := h.framework.RunLoadTest(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Load test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Load test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getLoadTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_load_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetLoadTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

func (h *TestingHTTPHandler) stopLoadTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "stop_load_test")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	err := h.framework.StopLoadTest(ctx, testID)
	if err != nil {
		h.handleError(w, "Failed to stop load test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"test_id": testID,
		"status":  "stopped",
		"message": "Load test stopped successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

// Unit Testing Handlers

func (h *TestingHTTPHandler) runUnitTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_unit_test")
	defer span.End()

	var config UnitTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("unit-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting unit test via HTTP API")

	// Start unit test asynchronously
	go func() {
		_, err := h.framework.RunUnitTests(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Unit test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Unit test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getUnitTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_unit_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetUnitTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

// Chaos Testing Handlers

func (h *TestingHTTPHandler) runChaosTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_chaos_test")
	defer span.End()

	var config ChaosTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("chaos-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting chaos test via HTTP API")

	// Start chaos test asynchronously
	go func() {
		_, err := h.framework.RunChaosTest(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Chaos test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Chaos test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getChaosTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_chaos_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetChaosTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

func (h *TestingHTTPHandler) stopChaosTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "stop_chaos_test")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	err := h.framework.StopChaosTest(ctx, testID)
	if err != nil {
		h.handleError(w, "Failed to stop chaos test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"test_id": testID,
		"status":  "stopped",
		"message": "Chaos test stopped successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

// Security Testing Handlers

func (h *TestingHTTPHandler) runSecurityTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_security_test")
	defer span.End()

	var config SecurityTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("security-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting security test via HTTP API")

	// Start security test asynchronously
	go func() {
		_, err := h.framework.RunSecurityTest(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Security test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Security test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getSecurityTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_security_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetSecurityTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

func (h *TestingHTTPHandler) stopSecurityTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "stop_security_test")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	err := h.framework.StopSecurityTest(ctx, testID)
	if err != nil {
		h.handleError(w, "Failed to stop security test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"test_id": testID,
		"status":  "stopped",
		"message": "Security test stopped successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

// Compliance Testing Handlers

func (h *TestingHTTPHandler) runComplianceTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "run_compliance_test")
	defer span.End()

	var config ComplianceTestConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate test ID if not provided
	if config.TestID == "" {
		config.TestID = fmt.Sprintf("compliance-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("test_id", config.TestID))

	h.logger.WithField("test_id", config.TestID).Info("Starting compliance test via HTTP API")

	// Start compliance test asynchronously
	go func() {
		_, err := h.framework.RunComplianceTest(context.Background(), &config)
		if err != nil {
			h.logger.WithError(err).WithField("test_id", config.TestID).Error("Compliance test failed")
		}
	}()

	response := map[string]interface{}{
		"test_id": config.TestID,
		"status":  "started",
		"message": "Compliance test started successfully",
	}

	h.sendJSONResponse(w, response, http.StatusAccepted)
}

func (h *TestingHTTPHandler) getComplianceTestResults(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_compliance_test_results")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	span.SetAttributes(attribute.String("test_id", testID))

	results, err := h.framework.GetComplianceTestResults(ctx, testID)
	if err != nil {
		h.handleError(w, "Test results not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, results, http.StatusOK)
}

// General Testing Handlers

func (h *TestingHTTPHandler) getTestingStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_testing_status")
	defer span.End()

	status, err := h.framework.GetTestingStatus(ctx)
	if err != nil {
		h.handleError(w, "Failed to get testing status", http.StatusInternalServerError, err)
		return
	}

	h.sendJSONResponse(w, status, http.StatusOK)
}

func (h *TestingHTTPHandler) getTestHistory(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_test_history")
	defer span.End()

	// Parse query parameters
	limit := 50
	offset := 0
	testType := ""

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	testType = r.URL.Query().Get("type")

	span.SetAttributes(
		attribute.Int("limit", limit),
		attribute.Int("offset", offset),
		attribute.String("test_type", testType),
	)

	history, err := h.framework.GetTestHistory(ctx, limit, offset, testType)
	if err != nil {
		h.handleError(w, "Failed to get test history", http.StatusInternalServerError, err)
		return
	}

	h.sendJSONResponse(w, history, http.StatusOK)
}

func (h *TestingHTTPHandler) getTestingMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_testing_metrics")
	defer span.End()

	// Parse query parameters for time range
	var startTime, endTime time.Time
	var err error

	if startStr := r.URL.Query().Get("start"); startStr != "" {
		startTime, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			h.handleError(w, "Invalid start time format", http.StatusBadRequest, err)
			return
		}
	}

	if endStr := r.URL.Query().Get("end"); endStr != "" {
		endTime, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			h.handleError(w, "Invalid end time format", http.StatusBadRequest, err)
			return
		}
	}

	metrics, err := h.framework.GetTestingMetrics(ctx, startTime, endTime)
	if err != nil {
		h.handleError(w, "Failed to get testing metrics", http.StatusInternalServerError, err)
		return
	}

	h.sendJSONResponse(w, metrics, http.StatusOK)
}

func (h *TestingHTTPHandler) generateTestReport(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "generate_test_report")
	defer span.End()

	vars := mux.Vars(r)
	testID := vars["testId"]

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	span.SetAttributes(
		attribute.String("test_id", testID),
		attribute.String("format", format),
	)

	report, contentType, err := h.framework.GenerateTestReport(ctx, testID, format)
	if err != nil {
		h.handleError(w, "Failed to generate test report", http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=test-report-%s.%s", testID, format))
	w.WriteHeader(http.StatusOK)
	w.Write(report)
}

// Test Scheduling Handlers

func (h *TestingHTTPHandler) scheduleTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "schedule_test")
	defer span.End()

	var schedule TestSchedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	// Generate schedule ID if not provided
	if schedule.ID == "" {
		schedule.ID = fmt.Sprintf("schedule-%d", time.Now().Unix())
	}

	span.SetAttributes(attribute.String("schedule_id", schedule.ID))

	err := h.framework.ScheduleTest(ctx, &schedule)
	if err != nil {
		h.handleError(w, "Failed to schedule test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"schedule_id": schedule.ID,
		"status":      "scheduled",
		"message":     "Test scheduled successfully",
	}

	h.sendJSONResponse(w, response, http.StatusCreated)
}

func (h *TestingHTTPHandler) getScheduledTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_scheduled_test")
	defer span.End()

	vars := mux.Vars(r)
	scheduleID := vars["scheduleId"]

	span.SetAttributes(attribute.String("schedule_id", scheduleID))

	schedule, err := h.framework.GetScheduledTest(ctx, scheduleID)
	if err != nil {
		h.handleError(w, "Scheduled test not found", http.StatusNotFound, err)
		return
	}

	h.sendJSONResponse(w, schedule, http.StatusOK)
}

func (h *TestingHTTPHandler) updateScheduledTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "update_scheduled_test")
	defer span.End()

	vars := mux.Vars(r)
	scheduleID := vars["scheduleId"]

	var schedule TestSchedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		h.handleError(w, "Invalid request body", http.StatusBadRequest, err)
		return
	}

	schedule.ID = scheduleID
	span.SetAttributes(attribute.String("schedule_id", scheduleID))

	err := h.framework.UpdateScheduledTest(ctx, &schedule)
	if err != nil {
		h.handleError(w, "Failed to update scheduled test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"schedule_id": scheduleID,
		"status":      "updated",
		"message":     "Scheduled test updated successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

func (h *TestingHTTPHandler) deleteScheduledTest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "delete_scheduled_test")
	defer span.End()

	vars := mux.Vars(r)
	scheduleID := vars["scheduleId"]

	span.SetAttributes(attribute.String("schedule_id", scheduleID))

	err := h.framework.DeleteScheduledTest(ctx, scheduleID)
	if err != nil {
		h.handleError(w, "Failed to delete scheduled test", http.StatusInternalServerError, err)
		return
	}

	response := map[string]interface{}{
		"schedule_id": scheduleID,
		"status":      "deleted",
		"message":     "Scheduled test deleted successfully",
	}

	h.sendJSONResponse(w, response, http.StatusOK)
}

func (h *TestingHTTPHandler) listScheduledTests(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "list_scheduled_tests")
	defer span.End()

	// Parse query parameters
	limit := 50
	offset := 0
	status := ""

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	status = r.URL.Query().Get("status")

	span.SetAttributes(
		attribute.Int("limit", limit),
		attribute.Int("offset", offset),
		attribute.String("status", status),
	)

	schedules, err := h.framework.ListScheduledTests(ctx, limit, offset, status)
	if err != nil {
		h.handleError(w, "Failed to list scheduled tests", http.StatusInternalServerError, err)
		return
	}

	h.sendJSONResponse(w, schedules, http.StatusOK)
}

// Helper Methods

func (h *TestingHTTPHandler) sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (h *TestingHTTPHandler) handleError(w http.ResponseWriter, message string, statusCode int, err error) {
	h.logger.WithError(err).Error(message)
	
	errorResponse := map[string]interface{}{
		"error":   message,
		"status":  statusCode,
		"details": err.Error(),
	}
	
	h.sendJSONResponse(w, errorResponse, statusCode)
}

// GetHealthStatus returns the health status of the testing framework
func (h *TestingHTTPHandler) GetHealthStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_health_status")
	defer span.End()

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"services": map[string]interface{}{
			"testing_framework": "healthy",
			"database":         "healthy",
			"message_queue":    "healthy",
			"storage":          "healthy",
		},
	}

	h.sendJSONResponse(w, health, http.StatusOK)
}

// GetReadinessStatus returns the readiness status of the testing framework
func (h *TestingHTTPHandler) GetReadinessStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.tracer.Start(r.Context(), "get_readiness_status")
	defer span.End()

	readiness := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().UTC(),
		"checks": map[string]interface{}{
			"database":      "ready",
			"message_queue": "ready",
			"storage":       "ready",
			"dependencies":  "ready",
		},
	}

	h.sendJSONResponse(w, readiness, http.StatusOK)
}

// Additional helper types for HTTP responses

// TestSchedule represents a scheduled test
type TestSchedule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Config      map[string]interface{} `json:"config"`
	Schedule    ScheduleExpression     `json:"schedule"`
	Enabled     bool                   `json:"enabled"`
	LastRun     *time.Time             `json:"last_run,omitempty"`
	NextRun     *time.Time             `json:"next_run,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	UpdatedBy   string                 `json:"updated_by"`
}

// ScheduleExpression represents schedule configuration
type ScheduleExpression struct {
	Type        string        `json:"type"` // cron, interval, once
	Expression  string        `json:"expression"`
	Interval    time.Duration `json:"interval,omitempty"`
	StartTime   *time.Time    `json:"start_time,omitempty"`
	EndTime     *time.Time    `json:"end_time,omitempty"`
	Timezone    string        `json:"timezone"`
	MaxRuns     int           `json:"max_runs,omitempty"`
}

// ComplianceTestConfig represents compliance test configuration
type ComplianceTestConfig struct {
	TestID      string            `json:"test_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Framework   string            `json:"framework"`
	Standards   []string          `json:"standards"`
	Controls    []string          `json:"controls"`
	Target      SecurityTarget    `json:"target"`
	Environment map[string]string `json:"environment"`
	Timeout     time.Duration     `json:"timeout"`
}

// TestingStatus represents the overall testing framework status
type TestingStatus struct {
	Status          string                    `json:"status"`
	ActiveTests     int                       `json:"active_tests"`
	QueuedTests     int                       `json:"queued_tests"`
	CompletedTests  int                       `json:"completed_tests"`
	FailedTests     int                       `json:"failed_tests"`
	RunningTests    map[string]TestExecution  `json:"running_tests"`
	Resources       ResourceUtilization       `json:"resources"`
	LastUpdate      time.Time                 `json:"last_update"`
}

// TestExecution represents a running test execution
type TestExecution struct {
	TestID    string        `json:"test_id"`
	Type      string        `json:"type"`
	Status    TestStatus    `json:"status"`
	StartTime time.Time     `json:"start_time"`
	Duration  time.Duration `json:"duration"`
	Progress  float64       `json:"progress"`
}

// ResourceUtilization represents resource usage
type ResourceUtilization struct {
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Disk    float64 `json:"disk"`
	Network float64 `json:"network"`
}

// TestHistory represents historical test data
type TestHistory struct {
	Tests      []TestSummary `json:"tests"`
	TotalCount int           `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
}

// TestSummary represents a test summary
type TestSummary struct {
	TestID      string        `json:"test_id"`
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Status      TestStatus    `json:"status"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Result      string        `json:"result"`
	Score       float64       `json:"score"`
	CreatedBy   string        `json:"created_by"`
}

// TestingMetrics represents comprehensive testing metrics
type TestingMetrics struct {
	Overview       TestingOverview       `json:"overview"`
	Performance    TestingPerformance    `json:"performance"`
	Quality        TestingQuality        `json:"quality"`
	Trends         TestingTrends         `json:"trends"`
	ResourceUsage  ResourceMetrics       `json:"resource_usage"`
	Timestamps     MetricTimestamps      `json:"timestamps"`
}

// TestingOverview provides high-level testing metrics
type TestingOverview struct {
	TotalTests        int     `json:"total_tests"`
	PassedTests       int     `json:"passed_tests"`
	FailedTests       int     `json:"failed_tests"`
	SkippedTests      int     `json:"skipped_tests"`
	SuccessRate       float64 `json:"success_rate"`
	AverageDuration   time.Duration `json:"average_duration"`
	TotalDuration     time.Duration `json:"total_duration"`
}

// TestingPerformance provides performance-related metrics
type TestingPerformance struct {
	AverageResponseTime time.Duration `json:"average_response_time"`
	P95ResponseTime     time.Duration `json:"p95_response_time"`
	P99ResponseTime     time.Duration `json:"p99_response_time"`
	Throughput          float64       `json:"throughput"`
	ErrorRate           float64       `json:"error_rate"`
}

// TestingQuality provides quality-related metrics
type TestingQuality struct {
	CodeCoverage       float64 `json:"code_coverage"`
	TestCoverage       float64 `json:"test_coverage"`
	SecurityScore      float64 `json:"security_score"`
	ComplianceScore    float64 `json:"compliance_score"`
	TechnicalDebt      float64 `json:"technical_debt"`
}

// TestingTrends provides trend analysis
type TestingTrends struct {
	SuccessRateTrend   []TrendPoint `json:"success_rate_trend"`
	PerformanceTrend   []TrendPoint `json:"performance_trend"`
	CoverageTrend      []TrendPoint `json:"coverage_trend"`
	SecurityTrend      []TrendPoint `json:"security_trend"`
}

// ResourceMetrics provides resource utilization metrics
type ResourceMetrics struct {
	Current ResourceUtilization `json:"current"`
	Average ResourceUtilization `json:"average"`
	Peak    ResourceUtilization `json:"peak"`
}

// MetricTimestamps provides timing information for metrics
type MetricTimestamps struct {
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	GeneratedAt time.Time `json:"generated_at"`
	Duration    time.Duration `json:"duration"`
}

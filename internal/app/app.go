package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/attestation"
	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/enterprise/distributed-health-monitor/internal/consensus"
	"github.com/enterprise/distributed-health-monitor/internal/policy"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// Application represents the main application
type Application struct {
	config    *config.Config
	logger    *logrus.Logger
	
	// Core services
	attestationService *attestation.Service
	consensusService   *consensus.ConsensusService
	policyEngine       policy.PolicyEngine
	
	// HTTP server
	httpServer *http.Server
	
	// Observability
	tracerProvider *trace.TracerProvider
	meterProvider  *metric.MeterProvider
	
	// State management
	running bool
	wg      sync.WaitGroup
	stopCh  chan struct{}
}

// New creates a new application instance
func New(ctx context.Context, cfg *config.Config, logger *logrus.Logger) (*Application, error) {
	app := &Application{
		config: cfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}

	// Initialize observability
	if err := app.initializeObservability(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize observability: %w", err)
	}

	// Initialize policy engine
	if cfg.Attestation.PolicyEngine.Enabled {
		policyEngine, err := policy.NewOPAPolicyEngine(cfg.Attestation.PolicyEngine, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
		}
		app.policyEngine = policyEngine
	}

	// Initialize consensus service
	if cfg.Consensus.Enabled {
		consensusService, err := consensus.NewConsensusService(&cfg.Consensus, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize consensus service: %w", err)
		}
		app.consensusService = consensusService
	}

	// Initialize attestation service
	attestationService, err := attestation.NewService(&cfg.Attestation, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation service: %w", err)
	}
	app.attestationService = attestationService

	// Initialize HTTP server
	if err := app.initializeHTTPServer(); err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	return app, nil
}

// Start starts the application
func (a *Application) Start(ctx context.Context) error {
	a.logger.Info("Starting application components")

	// Start consensus service first
	if a.consensusService != nil {
		if err := a.consensusService.Start(ctx); err != nil {
			return fmt.Errorf("failed to start consensus service: %w", err)
		}
	}

	// Start attestation service
	if err := a.attestationService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start attestation service: %w", err)
	}

	// Start HTTP server
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.startHTTPServer()
	}()

	a.running = true
	a.logger.Info("Application started successfully")

	return nil
}

// Stop stops the application
func (a *Application) Stop(ctx context.Context) error {
	if !a.running {
		return nil
	}

	a.logger.Info("Stopping application")

	close(a.stopCh)

	// Stop HTTP server
	if a.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		
		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			a.logger.WithError(err).Error("Failed to shutdown HTTP server")
		}
	}

	// Stop attestation service
	if a.attestationService != nil {
		if err := a.attestationService.Stop(ctx); err != nil {
			a.logger.WithError(err).Error("Failed to stop attestation service")
		}
	}

	// Stop consensus service
	if a.consensusService != nil {
		if err := a.consensusService.Stop(ctx); err != nil {
			a.logger.WithError(err).Error("Failed to stop consensus service")
		}
	}

	// Stop policy engine
	if a.policyEngine != nil {
		if err := a.policyEngine.Close(); err != nil {
			a.logger.WithError(err).Error("Failed to close policy engine")
		}
	}

	// Shutdown observability
	a.shutdownObservability(ctx)

	a.wg.Wait()
	a.running = false
	a.logger.Info("Application stopped")

	return nil
}

// initializeObservability sets up tracing and metrics
func (a *Application) initializeObservability(ctx context.Context) error {
	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(a.config.Tracing.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing
	if a.config.Tracing.Enabled {
		if err := a.initializeTracing(ctx, res); err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	// Initialize metrics
	if a.config.Metrics.Enabled {
		if err := a.initializeMetrics(ctx, res); err != nil {
			return fmt.Errorf("failed to initialize metrics: %w", err)
		}
	}

	return nil
}

// initializeTracing sets up OpenTelemetry tracing
func (a *Application) initializeTracing(ctx context.Context, res *resource.Resource) error {
	// Create Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(a.config.Tracing.Endpoint)))
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create tracer provider
	a.tracerProvider = trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(a.config.Tracing.SampleRate)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(a.tracerProvider)

	a.logger.Info("Tracing initialized")
	return nil
}

// initializeMetrics sets up OpenTelemetry metrics
func (a *Application) initializeMetrics(ctx context.Context, res *resource.Resource) error {
	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	// Create meter provider
	a.meterProvider = metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(exporter),
	)

	// Set global meter provider
	otel.SetMeterProvider(a.meterProvider)

	a.logger.Info("Metrics initialized")
	return nil
}

// initializeHTTPServer sets up the HTTP server with routes
func (a *Application) initializeHTTPServer() error {
	router := mux.NewRouter()

	// API routes
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	
	// Attestation endpoints
	apiRouter.HandleFunc("/attestation/request", a.handleAttestationRequest).Methods("POST")
	apiRouter.HandleFunc("/attestation/{id}", a.handleGetAttestation).Methods("GET")
	apiRouter.HandleFunc("/attestation/{id}/status", a.handleGetAttestationStatus).Methods("GET")
	
	// Policy endpoints
	apiRouter.HandleFunc("/policies", a.handleListPolicies).Methods("GET")
	apiRouter.HandleFunc("/policies/{id}", a.handleGetPolicy).Methods("GET")
	
	// Health and readiness endpoints
	router.HandleFunc("/health", a.handleHealth).Methods("GET")
	router.HandleFunc("/ready", a.handleReady).Methods("GET")
	router.HandleFunc("/metrics", promhttp.Handler().ServeHTTP).Methods("GET")

	// Consensus endpoints (if enabled)
	if a.consensusService != nil {
		apiRouter.HandleFunc("/cluster/status", a.handleClusterStatus).Methods("GET")
		apiRouter.HandleFunc("/cluster/peers", a.handleClusterPeers).Methods("GET")
	}

	// Create HTTP server
	a.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port),
		Handler:      router,
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
		IdleTimeout:  a.config.Server.IdleTimeout,
	}

	return nil
}

// startHTTPServer starts the HTTP server
func (a *Application) startHTTPServer() {
	a.logger.WithField("address", a.httpServer.Addr).Info("Starting HTTP server")

	var err error
	if a.config.Server.TLS.Enabled {
		err = a.httpServer.ListenAndServeTLS(a.config.Server.TLS.CertFile, a.config.Server.TLS.KeyFile)
	} else {
		err = a.httpServer.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		a.logger.WithError(err).Error("HTTP server failed")
	}
}

// shutdownObservability shuts down observability components
func (a *Application) shutdownObservability(ctx context.Context) {
	if a.tracerProvider != nil {
		if err := a.tracerProvider.Shutdown(ctx); err != nil {
			a.logger.WithError(err).Error("Failed to shutdown tracer provider")
		}
	}

	if a.meterProvider != nil {
		if err := a.meterProvider.Shutdown(ctx); err != nil {
			a.logger.WithError(err).Error("Failed to shutdown meter provider")
		}
	}
}

// HTTP Handlers

// handleAttestationRequest handles attestation requests
func (a *Application) handleAttestationRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var req attestation.AttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := a.attestationService.ProcessAttestationRequest(ctx, &req)
	if err != nil {
		a.logger.WithError(err).Error("Failed to process attestation request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetAttestation handles getting attestation results
func (a *Application) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	attestationID := vars["id"]

	// Implementation would retrieve attestation by ID
	// For now, return a placeholder response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":     attestationID,
		"status": "completed",
	})
}

// handleGetAttestationStatus handles getting attestation status
func (a *Application) handleGetAttestationStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	attestationID := vars["id"]

	// Implementation would retrieve attestation status by ID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":     attestationID,
		"status": "in_progress",
	})
}

// handleListPolicies handles listing policies
func (a *Application) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if a.policyEngine == nil {
		http.Error(w, "Policy engine not enabled", http.StatusServiceUnavailable)
		return
	}

	// Implementation would list all policies
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]string{
		{"id": "default", "name": "Default Policy"},
	})
}

// handleGetPolicy handles getting a specific policy
func (a *Application) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if a.policyEngine == nil {
		http.Error(w, "Policy engine not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]

	policy, err := a.policyEngine.GetPolicy(r.Context(), policyID)
	if err != nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// handleHealth handles health checks
func (a *Application) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"services": map[string]string{
			"attestation": "healthy",
		},
	}

	if a.consensusService != nil {
		if a.consensusService.IsLeader() {
			health["services"].(map[string]string)["consensus"] = "leader"
		} else {
			health["services"].(map[string]string)["consensus"] = "follower"
		}
	}

	if a.policyEngine != nil {
		health["services"].(map[string]string)["policy"] = "healthy"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleReady handles readiness checks
func (a *Application) handleReady(w http.ResponseWriter, r *http.Request) {
	if !a.running {
		http.Error(w, "Service not ready", http.StatusServiceUnavailable)
		return
	}

	ready := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ready)
}

// handleClusterStatus handles cluster status requests
func (a *Application) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if a.consensusService == nil {
		http.Error(w, "Consensus not enabled", http.StatusServiceUnavailable)
		return
	}

	status := map[string]interface{}{
		"is_leader": a.consensusService.IsLeader(),
		"leader":    a.consensusService.GetLeader(),
		"peers":     len(a.consensusService.GetPeers()),
		"state":     a.consensusService.GetClusterState(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleClusterPeers handles cluster peers requests
func (a *Application) handleClusterPeers(w http.ResponseWriter, r *http.Request) {
	if a.consensusService == nil {
		http.Error(w, "Consensus not enabled", http.StatusServiceUnavailable)
		return
	}

	peers := a.consensusService.GetPeers()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

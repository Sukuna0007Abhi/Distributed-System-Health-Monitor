package attestation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Service represents the main attestation service
type Service struct {
	config     *config.AttestationConfig
	logger     *logrus.Logger
	tracer     trace.Tracer
	
	// Core components
	attesters  map[EvidenceType]Attester
	verifiers  map[EvidenceType]Verifier
	policies   PolicyEngine
	cache      EvidenceCache
	events     EventPublisher
	
	// Multi-tenant support
	tenants    map[string]*TenantConfig
	tenantsMux sync.RWMutex
	
	// Metrics and monitoring
	metrics    *AttestationMetrics
	
	// Processing queues by QoS level
	highPriorityQueue   chan *AttestationRequest
	mediumPriorityQueue chan *AttestationRequest
	lowPriorityQueue    chan *AttestationRequest
	
	// Worker pools
	workers     []*Worker
	workerCount int
	
	// State management
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// TenantConfig represents configuration for a specific tenant
type TenantConfig struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Policies        []string               `json:"policies"`
	TrustPolicy     *TrustPolicy           `json:"trust_policy"`
	QuotaLimits     QuotaLimits            `json:"quota_limits"`
	SecurityLevel   string                 `json:"security_level"`
	ComplianceReqs  []string               `json:"compliance_requirements"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// QuotaLimits defines resource limits for tenants
type QuotaLimits struct {
	MaxRequestsPerMinute int     `json:"max_requests_per_minute"`
	MaxRequestsPerHour   int     `json:"max_requests_per_hour"`
	MaxConcurrentReqs    int     `json:"max_concurrent_requests"`
	MaxEvidenceSize      int64   `json:"max_evidence_size"`
	QoSLimits           QoSLimits `json:"qos_limits"`
}

// QoSLimits defines QoS-specific limits
type QoSLimits struct {
	HighPriorityQuota   int `json:"high_priority_quota"`
	MediumPriorityQuota int `json:"medium_priority_quota"`
	LowPriorityQuota    int `json:"low_priority_quota"`
}

// Worker represents a worker for processing attestation requests
type Worker struct {
	id      int
	service *Service
	stopCh  chan struct{}
}

// NewService creates a new attestation service
func NewService(cfg *config.AttestationConfig, logger *logrus.Logger) (*Service, error) {
	tracer := otel.Tracer("attestation-service")
	
	service := &Service{
		config:    cfg,
		logger:    logger,
		tracer:    tracer,
		attesters: make(map[EvidenceType]Attester),
		verifiers: make(map[EvidenceType]Verifier),
		tenants:   make(map[string]*TenantConfig),
		stopCh:    make(chan struct{}),
		
		// Initialize queues with buffer sizes based on configuration
		highPriorityQueue:   make(chan *AttestationRequest, cfg.MaxConcurrentVerify/3),
		mediumPriorityQueue: make(chan *AttestationRequest, cfg.MaxConcurrentVerify/3),
		lowPriorityQueue:    make(chan *AttestationRequest, cfg.MaxConcurrentVerify/3),
		
		workerCount: cfg.MaxConcurrentVerify,
	}
	
	// Initialize metrics
	metrics, err := NewAttestationMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	service.metrics = metrics
	
	// Initialize policy engine
	if cfg.PolicyEngine.Enabled {
		policyEngine, err := NewOPAPolicyEngine(cfg.PolicyEngine, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
		}
		service.policies = policyEngine
	}
	
	// Initialize cache
	if cfg.CacheEnabled {
		cache, err := NewRedisEvidenceCache(cfg.CacheTTL)
		if err != nil {
			logger.Warnf("Failed to initialize Redis cache, falling back to memory cache: %v", err)
			service.cache = NewMemoryEvidenceCache(cfg.CacheTTL)
		} else {
			service.cache = cache
		}
	} else {
		service.cache = NewMemoryEvidenceCache(cfg.CacheTTL)
	}
	
	// Initialize event publisher
	eventPublisher, err := NewNATSEventPublisher(logger)
	if err != nil {
		logger.Warnf("Failed to initialize NATS event publisher: %v", err)
		service.events = NewNoOpEventPublisher()
	} else {
		service.events = eventPublisher
	}
	
	// Register default attesters and verifiers
	if err := service.registerDefaultComponents(); err != nil {
		return nil, fmt.Errorf("failed to register default components: %w", err)
	}
	
	return service, nil
}

// Start starts the attestation service
func (s *Service) Start(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "attestation.service.start")
	defer span.End()
	
	s.logger.Info("Starting attestation service")
	
	// Start worker pool
	s.workers = make([]*Worker, s.workerCount)
	for i := 0; i < s.workerCount; i++ {
		worker := &Worker{
			id:      i,
			service: s,
			stopCh:  make(chan struct{}),
		}
		s.workers[i] = worker
		
		s.wg.Add(1)
		go worker.run()
	}
	
	// Start queue processor
	s.wg.Add(1)
	go s.processQueues()
	
	// Start metrics collection
	s.wg.Add(1)
	go s.collectMetrics()
	
	s.running = true
	s.logger.Info("Attestation service started successfully")
	
	return nil
}

// Stop stops the attestation service
func (s *Service) Stop(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "attestation.service.stop")
	defer span.End()
	
	s.logger.Info("Stopping attestation service")
	
	s.running = false
	close(s.stopCh)
	
	// Stop all workers
	for _, worker := range s.workers {
		close(worker.stopCh)
	}
	
	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		s.logger.Info("Attestation service stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("Attestation service stop timeout reached")
		return ctx.Err()
	}
	
	return nil
}

// ProcessAttestationRequest processes an attestation request
func (s *Service) ProcessAttestationRequest(ctx context.Context, req *AttestationRequest) (*AttestationResponse, error) {
	ctx, span := s.tracer.Start(ctx, "attestation.process_request",
		trace.WithAttributes(
			attribute.String("request.id", req.ID),
			attribute.String("tenant.id", req.TenantID),
			attribute.String("qos.level", string(req.QoSLevel)),
		))
	defer span.End()
	
	startTime := time.Now()
	
	// Validate request
	if err := ValidateAttestationRequest(req); err != nil {
		s.metrics.RecordRequestValidationError()
		return s.createErrorResponse(req, "VALIDATION_ERROR", err.Error()), nil
	}
	
	// Check tenant configuration and quotas
	if err := s.validateTenantRequest(req); err != nil {
		s.metrics.RecordQuotaExceeded(req.TenantID)
		return s.createErrorResponse(req, "QUOTA_EXCEEDED", err.Error()), nil
	}
	
	// Publish attestation requested event
	event := NewAttestationEvent(req.TenantID, EventAttestationRequested, "attestation-service", req.TargetID)
	event.Data["request_id"] = req.ID
	event.Data["evidence_types"] = req.EvidenceTypes
	s.events.PublishEvent(ctx, event)
	
	// Check cache for existing valid evidence
	if s.config.CacheEnabled {
		if cachedResponse := s.checkCache(ctx, req); cachedResponse != nil {
			s.metrics.RecordCacheHit(req.TenantID)
			s.logger.WithField("request_id", req.ID).Debug("Returning cached attestation result")
			return cachedResponse, nil
		}
		s.metrics.RecordCacheMiss(req.TenantID)
	}
	
	// Route request to appropriate queue based on QoS level
	select {
	case <-ctx.Done():
		return s.createErrorResponse(req, "TIMEOUT", "Request timeout"), ctx.Err()
	default:
		switch req.QoSLevel {
		case QoSHigh:
			select {
			case s.highPriorityQueue <- req:
			default:
				return s.createErrorResponse(req, "QUEUE_FULL", "High priority queue is full"), nil
			}
		case QoSMedium:
			select {
			case s.mediumPriorityQueue <- req:
			default:
				return s.createErrorResponse(req, "QUEUE_FULL", "Medium priority queue is full"), nil
			}
		case QoSLow:
			select {
			case s.lowPriorityQueue <- req:
			default:
				return s.createErrorResponse(req, "QUEUE_FULL", "Low priority queue is full"), nil
			}
		}
	}
	
	// For synchronous processing, wait for result
	// In a production system, this would be handled asynchronously
	response := s.processRequestSync(ctx, req)
	
	// Record metrics
	processingTime := time.Since(startTime)
	s.metrics.RecordProcessingLatency(req.TenantID, string(req.QoSLevel), processingTime)
	s.metrics.RecordRequestProcessed(req.TenantID, string(response.Status))
	
	// Cache successful results
	if s.config.CacheEnabled && response.Status == StatusCompleted && response.Result == ResultTrusted {
		s.cacheResponse(ctx, req, response)
	}
	
	return response, nil
}

// processRequestSync processes a request synchronously
func (s *Service) processRequestSync(ctx context.Context, req *AttestationRequest) *AttestationResponse {
	response := &AttestationResponse{
		ID:        fmt.Sprintf("resp_%s", req.ID),
		RequestID: req.ID,
		TenantID:  req.TenantID,
		Status:    StatusInProgress,
		Timestamp: time.Now(),
		Metadata: AttestationMetadata{
			VerifierID: "attestation-service",
		},
	}
	
	// Collect evidence from attesters
	evidence, err := s.collectEvidence(ctx, req)
	if err != nil {
		response.Status = StatusFailed
		response.Error = &AttestationError{
			Code:      "EVIDENCE_COLLECTION_FAILED",
			Message:   "Failed to collect evidence",
			Details:   err.Error(),
			Timestamp: time.Now(),
		}
		return response
	}
	
	response.Evidence = evidence
	
	// Verify evidence
	verificationResults, err := s.verifyEvidence(ctx, evidence, req)
	if err != nil {
		response.Status = StatusFailed
		response.Error = &AttestationError{
			Code:      "VERIFICATION_FAILED",
			Message:   "Failed to verify evidence",
			Details:   err.Error(),
			Timestamp: time.Now(),
		}
		return response
	}
	
	// Evaluate policy if configured
	if s.policies != nil {
		policyResult, err := s.evaluatePolicy(ctx, req, evidence, verificationResults)
		if err != nil {
			s.logger.WithError(err).Warn("Policy evaluation failed")
		}
		response.PolicyResult = policyResult
	}
	
	// Determine final result
	response.Result = s.determineAttestationResult(verificationResults, response.PolicyResult)
	response.Status = StatusCompleted
	response.VerifiedAt = time.Now()
	response.ValidUntil = time.Now().Add(5 * time.Minute) // Default validity period
	
	// Update metadata
	response.Metadata.ProcessingTime = time.Since(response.Timestamp)
	response.Metadata.EvidenceSize = s.calculateEvidenceSize(evidence)
	response.Metadata.TrustLevel = s.calculateTrustLevel(verificationResults)
	
	// Publish completion event
	eventType := EventAttestationCompleted
	if response.Result != ResultTrusted {
		eventType = EventAttestationFailed
	}
	
	event := NewAttestationEvent(req.TenantID, eventType, "attestation-service", req.TargetID)
	event.Data["request_id"] = req.ID
	event.Data["result"] = response.Result
	event.Data["trust_level"] = response.Metadata.TrustLevel
	s.events.PublishEvent(ctx, event)
	
	return response
}

// processQueues processes requests from different priority queues
func (s *Service) processQueues() {
	defer s.wg.Done()
	
	for {
		select {
		case <-s.stopCh:
			return
		case req := <-s.highPriorityQueue:
			s.processQueuedRequest(req)
		case req := <-s.mediumPriorityQueue:
			select {
			case req2 := <-s.highPriorityQueue:
				// Prioritize high priority requests
				s.processQueuedRequest(req2)
				s.processQueuedRequest(req)
			default:
				s.processQueuedRequest(req)
			}
		case req := <-s.lowPriorityQueue:
			select {
			case req2 := <-s.highPriorityQueue:
				s.processQueuedRequest(req2)
				s.processQueuedRequest(req)
			case req2 := <-s.mediumPriorityQueue:
				s.processQueuedRequest(req2)
				s.processQueuedRequest(req)
			default:
				s.processQueuedRequest(req)
			}
		}
	}
}

// Worker methods

// run starts the worker
func (w *Worker) run() {
	defer w.service.wg.Done()
	
	w.service.logger.WithField("worker_id", w.id).Debug("Worker started")
	
	for {
		select {
		case <-w.stopCh:
			w.service.logger.WithField("worker_id", w.id).Debug("Worker stopped")
			return
		default:
			// Worker processes requests from the service
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Helper methods

func (s *Service) processQueuedRequest(req *AttestationRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.VerificationTimeout)
	defer cancel()
	
	// Process the request asynchronously
	go func() {
		response := s.processRequestSync(ctx, req)
		// In a real implementation, this would be stored and made available to the client
		s.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"status":     response.Status,
			"result":     response.Result,
		}).Debug("Processed queued attestation request")
	}()
}

func (s *Service) registerDefaultComponents() error {
	// Register TPM attester/verifier
	tpmAttester := NewTPMAttester(s.config.Hardware, s.logger)
	tpmVerifier := NewTPMVerifier(s.config.Hardware, s.logger)
	
	s.attesters[EvidenceTypeTPM] = tpmAttester
	s.verifiers[EvidenceTypeTPM] = tpmVerifier
	
	// Register container attester/verifier
	containerAttester := NewContainerAttester(s.logger)
	containerVerifier := NewContainerVerifier(s.logger)
	
	s.attesters[EvidenceTypeContainer] = containerAttester
	s.verifiers[EvidenceTypeContainer] = containerVerifier
	
	// Register software attester/verifier
	softwareAttester := NewSoftwareAttester(s.logger)
	softwareVerifier := NewSoftwareVerifier(s.logger)
	
	s.attesters[EvidenceTypeSoftware] = softwareAttester
	s.verifiers[EvidenceTypeSoftware] = softwareVerifier
	
	return nil
}

func (s *Service) validateTenantRequest(req *AttestationRequest) error {
	s.tenantsMux.RLock()
	tenant, exists := s.tenants[req.TenantID]
	s.tenantsMux.RUnlock()
	
	if !exists {
		// Create default tenant configuration
		tenant = &TenantConfig{
			ID:   req.TenantID,
			Name: fmt.Sprintf("Tenant %s", req.TenantID),
			QuotaLimits: QuotaLimits{
				MaxRequestsPerMinute: 1000,
				MaxRequestsPerHour:   10000,
				MaxConcurrentReqs:    10,
				MaxEvidenceSize:      1024 * 1024, // 1MB
			},
			SecurityLevel: "standard",
			CreatedAt:     time.Now(),
		}
		
		s.tenantsMux.Lock()
		s.tenants[req.TenantID] = tenant
		s.tenantsMux.Unlock()
	}
	
	// Check quotas (simplified implementation)
	// In production, this would involve more sophisticated rate limiting
	return nil
}

func (s *Service) checkCache(ctx context.Context, req *AttestationRequest) *AttestationResponse {
	cacheKey := s.generateCacheKey(req)
	
	if cachedData, found := s.cache.Get(ctx, cacheKey); found {
		var response AttestationResponse
		if err := json.Unmarshal(cachedData, &response); err == nil {
			if response.ValidUntil.After(time.Now()) {
				return &response
			}
		}
	}
	
	return nil
}

func (s *Service) cacheResponse(ctx context.Context, req *AttestationRequest, response *AttestationResponse) {
	cacheKey := s.generateCacheKey(req)
	
	if data, err := json.Marshal(response); err == nil {
		s.cache.Set(ctx, cacheKey, data, s.config.CacheTTL)
	}
}

func (s *Service) generateCacheKey(req *AttestationRequest) string {
	return fmt.Sprintf("attestation:%s:%s:%v", req.TenantID, req.TargetID, req.EvidenceTypes)
}

func (s *Service) createErrorResponse(req *AttestationRequest, code, message string) *AttestationResponse {
	return &AttestationResponse{
		ID:        fmt.Sprintf("resp_%s", req.ID),
		RequestID: req.ID,
		TenantID:  req.TenantID,
		Status:    StatusFailed,
		Result:    ResultUnknown,
		Timestamp: time.Now(),
		Error: &AttestationError{
			Code:      code,
			Message:   message,
			Timestamp: time.Now(),
		},
		Metadata: AttestationMetadata{
			VerifierID: "attestation-service",
		},
	}
}

func (s *Service) collectEvidence(ctx context.Context, req *AttestationRequest) ([]*Evidence, error) {
	var evidence []*Evidence
	var mu sync.Mutex
	var wg sync.WaitGroup
	var lastErr error
	
	for _, evidenceType := range req.EvidenceTypes {
		attester, exists := s.attesters[evidenceType]
		if !exists {
			s.logger.WithField("evidence_type", evidenceType).Warn("No attester available for evidence type")
			continue
		}
		
		wg.Add(1)
		go func(et EvidenceType, att Attester) {
			defer wg.Done()
			
			evidenceReq := &EvidenceRequest{
				ID:            fmt.Sprintf("ev_%s_%s", req.ID, et),
				RequesterID:   req.RequesterID,
				EvidenceTypes: []EvidenceType{et},
				Nonce:         req.Nonce,
				Context:       req.Context,
				Timestamp:     time.Now(),
			}
			
			ev, err := att.GenerateEvidence(ctx, evidenceReq)
			if err != nil {
				s.logger.WithError(err).WithField("evidence_type", et).Error("Failed to generate evidence")
				mu.Lock()
				lastErr = err
				mu.Unlock()
				return
			}
			
			mu.Lock()
			evidence = append(evidence, ev)
			mu.Unlock()
		}(evidenceType, attester)
	}
	
	wg.Wait()
	
	if len(evidence) == 0 {
		return nil, fmt.Errorf("failed to collect any evidence: %w", lastErr)
	}
	
	return evidence, nil
}

func (s *Service) verifyEvidence(ctx context.Context, evidence []*Evidence, req *AttestationRequest) ([]*VerificationResult, error) {
	var results []*VerificationResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	for _, ev := range evidence {
		verifier, exists := s.verifiers[ev.Type]
		if !exists {
			s.logger.WithField("evidence_type", ev.Type).Warn("No verifier available for evidence type")
			continue
		}
		
		wg.Add(1)
		go func(evidence *Evidence, ver Verifier) {
			defer wg.Done()
			
			// Get policy for verification
			var policy *Policy
			if s.policies != nil {
				p, err := s.policies.GetPolicy(ctx, req.PolicyID)
				if err != nil {
					s.logger.WithError(err).Warn("Failed to get policy, using default")
					policy = s.getDefaultPolicy()
				} else {
					policy = p
				}
			} else {
				policy = s.getDefaultPolicy()
			}
			
			result, err := ver.VerifyEvidence(ctx, evidence, policy)
			if err != nil {
				s.logger.WithError(err).WithField("evidence_type", evidence.Type).Error("Failed to verify evidence")
				result = &VerificationResult{
					Verified:   false,
					TrustLevel: 0.0,
					VerifiedAt: time.Now(),
				}
			}
			
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(ev, verifier)
	}
	
	wg.Wait()
	
	return results, nil
}

func (s *Service) evaluatePolicy(ctx context.Context, req *AttestationRequest, evidence []*Evidence, results []*VerificationResult) (*PolicyEvaluationResult, error) {
	if s.policies == nil {
		return nil, fmt.Errorf("policy engine not configured")
	}
	
	return s.policies.EvaluatePolicy(ctx, req.PolicyID, evidence, results)
}

func (s *Service) determineAttestationResult(results []*VerificationResult, policyResult *PolicyEvaluationResult) AttestationResult {
	if policyResult != nil && policyResult.Decision == DecisionDeny {
		return ResultPolicyViolation
	}
	
	trusted := 0
	total := len(results)
	
	for _, result := range results {
		if result.Verified && result.TrustLevel >= 0.7 {
			trusted++
		}
	}
	
	if total == 0 {
		return ResultUnknown
	}
	
	ratio := float64(trusted) / float64(total)
	if ratio >= 0.8 {
		return ResultTrusted
	} else if ratio >= 0.5 {
		return ResultInconclusive
	}
	
	return ResultUntrusted
}

func (s *Service) calculateEvidenceSize(evidence []*Evidence) int64 {
	var size int64
	for _, ev := range evidence {
		size += int64(len(ev.Raw))
	}
	return size
}

func (s *Service) calculateTrustLevel(results []*VerificationResult) float64 {
	if len(results) == 0 {
		return 0.0
	}
	
	var sum float64
	for _, result := range results {
		sum += result.TrustLevel
	}
	
	return sum / float64(len(results))
}

func (s *Service) getDefaultPolicy() *Policy {
	return &Policy{
		ID:      "default",
		Name:    "Default Attestation Policy",
		Version: "1.0",
		Rules: []PolicyRule{
			{
				ID:        "trust_threshold",
				Name:      "Minimum Trust Threshold",
				Condition: "trust_level >= 0.7",
				Action:    ActionAllow,
				Severity:  "high",
			},
		},
		CreatedAt:  time.Now(),
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(365 * 24 * time.Hour),
	}
}

func (s *Service) collectMetrics() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Collect queue sizes
			s.metrics.RecordQueueSize("high", len(s.highPriorityQueue))
			s.metrics.RecordQueueSize("medium", len(s.mediumPriorityQueue))
			s.metrics.RecordQueueSize("low", len(s.lowPriorityQueue))
			
			// Collect worker status
			activeWorkers := 0
			for _, worker := range s.workers {
				select {
				case <-worker.stopCh:
					// Worker is stopped
				default:
					activeWorkers++
				}
			}
			s.metrics.RecordActiveWorkers(activeWorkers)
		}
	}
}

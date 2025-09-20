package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SPIFFEManager manages SPIFFE/SPIRE integration for workload identity
type SPIFFEManager interface {
	// Initialize the SPIFFE manager
	Initialize(ctx context.Context) error
	
	// Get X.509 SVID for workload authentication
	GetX509SVID(ctx context.Context) (*x509svid.SVID, error)
	
	// Get JWT SVID for service-to-service authentication
	GetJWTSVID(ctx context.Context, audience []string) (*jwtsvid.SVID, error)
	
	// Validate SPIFFE ID for incoming requests
	ValidateSPIFFEID(ctx context.Context, spiffeID string) (*ValidationResult, error)
	
	// Get workload attestation data
	GetWorkloadAttestation(ctx context.Context, workloadID string) (*WorkloadAttestation, error)
	
	// Register workload for attestation
	RegisterWorkload(ctx context.Context, workload *WorkloadRegistration) error
	
	// Get trust domain information
	GetTrustDomain() spiffeid.TrustDomain
	
	// Start background services
	Start(ctx context.Context) error
	
	// Stop services
	Stop(ctx context.Context) error
}

// ValidationResult represents SPIFFE ID validation result
type ValidationResult struct {
	Valid         bool                   `json:"valid"`
	SPIFFEID      spiffeid.ID            `json:"spiffe_id"`
	TrustDomain   spiffeid.TrustDomain   `json:"trust_domain"`
	Path          string                 `json:"path"`
	Claims        map[string]interface{} `json:"claims"`
	Selectors     []string               `json:"selectors"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Attestations  []string               `json:"attestations"`
	TrustLevel    TrustLevel             `json:"trust_level"`
	Warnings      []string               `json:"warnings"`
	Errors        []string               `json:"errors"`
}

// WorkloadAttestation represents workload attestation data
type WorkloadAttestation struct {
	WorkloadID    string                 `json:"workload_id"`
	SPIFFEID      spiffeid.ID            `json:"spiffe_id"`
	Selectors     []WorkloadSelector     `json:"selectors"`
	Attestations  []AttestationEntry     `json:"attestations"`
	FederatedWith []spiffeid.TrustDomain `json:"federated_with"`
	TTL           time.Duration          `json:"ttl"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Status        WorkloadStatus         `json:"status"`
}

// WorkloadRegistration represents workload registration request
type WorkloadRegistration struct {
	WorkloadID      string             `json:"workload_id"`
	SPIFFEID        string             `json:"spiffe_id"`
	Selectors       []WorkloadSelector `json:"selectors"`
	TTL             time.Duration      `json:"ttl"`
	FederatesWith   []string           `json:"federates_with"`
	DNSNames        []string           `json:"dns_names"`
	StoreSVID       bool               `json:"store_svid"`
	RotationPolicy  RotationPolicy     `json:"rotation_policy"`
}

// WorkloadSelector represents workload selection criteria
type WorkloadSelector struct {
	Type   string `json:"type"`   // k8s, docker, unix, etc.
	Value  string `json:"value"`  // specific selector value
}

// AttestationEntry represents an attestation entry
type AttestationEntry struct {
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Validated   bool                   `json:"validated"`
}

// TrustLevel represents trust level for SPIFFE identities
type TrustLevel int

const (
	TrustLevelUntrusted TrustLevel = iota
	TrustLevelLow
	TrustLevelMedium
	TrustLevelHigh
	TrustLevelCritical
)

func (t TrustLevel) String() string {
	switch t {
	case TrustLevelUntrusted:
		return "untrusted"
	case TrustLevelLow:
		return "low"
	case TrustLevelMedium:
		return "medium"
	case TrustLevelHigh:
		return "high"
	case TrustLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// WorkloadStatus represents workload status
type WorkloadStatus int

const (
	WorkloadStatusUnknown WorkloadStatus = iota
	WorkloadStatusActive
	WorkloadStatusInactive
	WorkloadStatusSuspended
	WorkloadStatusRevoked
)

func (w WorkloadStatus) String() string {
	switch w {
	case WorkloadStatusActive:
		return "active"
	case WorkloadStatusInactive:
		return "inactive"
	case WorkloadStatusSuspended:
		return "suspended"
	case WorkloadStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// RotationPolicy defines SVID rotation policy
type RotationPolicy struct {
	Enabled       bool          `json:"enabled"`
	RotateBefore  time.Duration `json:"rotate_before"`
	MaxAge        time.Duration `json:"max_age"`
	AutoRotate    bool          `json:"auto_rotate"`
	NotifyBefore  time.Duration `json:"notify_before"`
}

// DefaultSPIFFEManager implements SPIFFEManager
type DefaultSPIFFEManager struct {
	mu           sync.RWMutex
	logger       *logrus.Logger
	config       *SPIFFEConfig
	
	// SPIFFE components
	workloadAPI  *workloadapi.Client
	trustDomain  spiffeid.TrustDomain
	
	// Current SVIDs
	x509SVID     *x509svid.SVID
	jwtSVID      *jwtsvid.SVID
	
	// Workload registry
	workloads    map[string]*WorkloadAttestation
	
	// Metrics
	meter        metric.Meter
	
	// State
	initialized  bool
	running      bool
	stopCh       chan struct{}
}

// SPIFFEConfig configures SPIFFE integration
type SPIFFEConfig struct {
	// SPIRE configuration
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	SocketPath     string `yaml:"socket_path" json:"socket_path"`
	TrustDomain    string `yaml:"trust_domain" json:"trust_domain"`
	ServerAddress  string `yaml:"server_address" json:"server_address"`
	
	// Workload configuration
	WorkloadID     string        `yaml:"workload_id" json:"workload_id"`
	ServiceName    string        `yaml:"service_name" json:"service_name"`
	TTL            time.Duration `yaml:"ttl" json:"ttl"`
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
	
	// Rotation policy
	AutoRotation   RotationPolicy `yaml:"auto_rotation" json:"auto_rotation"`
	
	// Federation
	FederatedTrustDomains []string `yaml:"federated_trust_domains" json:"federated_trust_domains"`
	
	// Attestation
	NodeAttestation    NodeAttestationConfig    `yaml:"node_attestation" json:"node_attestation"`
	WorkloadAttestation WorkloadAttestationConfig `yaml:"workload_attestation" json:"workload_attestation"`
	
	// Validation
	ValidateWorkloads  bool     `yaml:"validate_workloads" json:"validate_workloads"`
	AllowedSVIDTypes   []string `yaml:"allowed_svid_types" json:"allowed_svid_types"`
	RequiredSelectors  []string `yaml:"required_selectors" json:"required_selectors"`
}

// NodeAttestationConfig configures node attestation
type NodeAttestationConfig struct {
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	Plugins    []string          `yaml:"plugins" json:"plugins"`
	Config     map[string]string `yaml:"config" json:"config"`
	Timeout    time.Duration     `yaml:"timeout" json:"timeout"`
}

// WorkloadAttestationConfig configures workload attestation
type WorkloadAttestationConfig struct {
	Enabled          bool              `yaml:"enabled" json:"enabled"`
	Plugins          []string          `yaml:"plugins" json:"plugins"`
	Config           map[string]string `yaml:"config" json:"config"`
	RequireAttestation bool            `yaml:"require_attestation" json:"require_attestation"`
	ValidateSelectors  bool            `yaml:"validate_selectors" json:"validate_selectors"`
}

// NewSPIFFEManager creates a new SPIFFE manager
func NewSPIFFEManager(config *SPIFFEConfig, logger *logrus.Logger) (*DefaultSPIFFEManager, error) {
	if config == nil {
		config = &SPIFFEConfig{
			Enabled:         true,
			SocketPath:      "/tmp/spire-agent/public/api.sock",
			TrustDomain:     "enterprise.local",
			TTL:             time.Hour,
			RefreshInterval: 30 * time.Minute,
			AutoRotation: RotationPolicy{
				Enabled:      true,
				RotateBefore: 10 * time.Minute,
				MaxAge:       24 * time.Hour,
				AutoRotate:   true,
				NotifyBefore: 15 * time.Minute,
			},
			AllowedSVIDTypes: []string{"x509", "jwt"},
		}
	}

	// Parse trust domain
	trustDomain, err := spiffeid.TrustDomainFromString(config.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	return &DefaultSPIFFEManager{
		logger:      logger,
		config:      config,
		trustDomain: trustDomain,
		workloads:   make(map[string]*WorkloadAttestation),
		meter:       otel.Meter("spiffe"),
		stopCh:      make(chan struct{}),
	}, nil
}

// Initialize initializes the SPIFFE manager
func (s *DefaultSPIFFEManager) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return fmt.Errorf("SPIFFE manager already initialized")
	}

	s.logger.Info("Initializing SPIFFE manager")

	// Create workload API client
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(s.config.SocketPath))
	if err != nil {
		return fmt.Errorf("failed to create workload API client: %w", err)
	}
	s.workloadAPI = client

	// Get initial X.509 SVID
	x509SVID, err := s.workloadAPI.FetchX509SVID(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch X.509 SVID: %w", err)
	}
	s.x509SVID = x509SVID

	s.initialized = true
	s.logger.WithFields(logrus.Fields{
		"trust_domain": s.trustDomain.String(),
		"spiffe_id":    x509SVID.ID.String(),
		"expires_at":   x509SVID.Certificates[0].NotAfter,
	}).Info("SPIFFE manager initialized")

	return nil
}

// GetX509SVID returns the current X.509 SVID
func (s *DefaultSPIFFEManager) GetX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("SPIFFE manager not initialized")
	}

	// Check if SVID needs rotation
	if s.needsRotation(s.x509SVID.Certificates[0]) {
		s.mu.RUnlock()
		s.mu.Lock()
		defer func() {
			s.mu.Unlock()
			s.mu.RLock()
		}()

		// Fetch new SVID
		newSVID, err := s.workloadAPI.FetchX509SVID(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to rotate X.509 SVID: %w", err)
		}
		s.x509SVID = newSVID

		s.logger.WithField("new_expires_at", newSVID.Certificates[0].NotAfter).Info("X.509 SVID rotated")
	}

	return s.x509SVID, nil
}

// GetJWTSVID returns a JWT SVID for the specified audience
func (s *DefaultSPIFFEManager) GetJWTSVID(ctx context.Context, audience []string) (*jwtsvid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("SPIFFE manager not initialized")
	}

	tracer := otel.Tracer("spiffe")
	ctx, span := tracer.Start(ctx, "get_jwt_svid")
	defer span.End()

	span.SetAttributes(
		attribute.StringSlice("audience", audience),
		attribute.String("trust_domain", s.trustDomain.String()),
	)

	// Fetch JWT SVID
	jwtSVID, err := s.workloadAPI.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"audience":   audience,
		"expires_at": jwtSVID.Expiry,
	}).Debug("JWT SVID fetched")

	return jwtSVID, nil
}

// ValidateSPIFFEID validates a SPIFFE ID and returns validation results
func (s *DefaultSPIFFEManager) ValidateSPIFFEID(ctx context.Context, spiffeIDStr string) (*ValidationResult, error) {
	result := &ValidationResult{
		Claims:       make(map[string]interface{}),
		Selectors:    make([]string, 0),
		Attestations: make([]string, 0),
		Warnings:     make([]string, 0),
		Errors:       make([]string, 0),
	}

	// Parse SPIFFE ID
	spiffeID, err := spiffeid.FromString(spiffeIDStr)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid SPIFFE ID format: %v", err))
		return result, nil
	}

	result.SPIFFEID = spiffeID
	result.TrustDomain = spiffeID.TrustDomain()
	result.Path = spiffeID.Path()

	// Validate trust domain
	if spiffeID.TrustDomain() != s.trustDomain {
		// Check if it's a federated trust domain
		federated := false
		for _, federatedTD := range s.config.FederatedTrustDomains {
			if federatedTrustDomain, err := spiffeid.TrustDomainFromString(federatedTD); err == nil {
				if spiffeID.TrustDomain() == federatedTrustDomain {
					federated = true
					break
				}
			}
		}

		if !federated {
			result.Valid = false
			result.Errors = append(result.Errors, "SPIFFE ID from untrusted domain")
			result.TrustLevel = TrustLevelUntrusted
			return result, nil
		} else {
			result.Warnings = append(result.Warnings, "SPIFFE ID from federated trust domain")
			result.TrustLevel = TrustLevelMedium
		}
	} else {
		result.TrustLevel = TrustLevelHigh
	}

	// Validate path format
	if err := s.validateSPIFFEPath(spiffeID.Path()); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Path validation warning: %v", err))
		if result.TrustLevel > TrustLevelMedium {
			result.TrustLevel = TrustLevelMedium
		}
	}

	// Check workload registration
	workload := s.findWorkloadBySpiffeID(spiffeID)
	if workload != nil {
		result.Selectors = s.extractSelectorsAsStrings(workload.Selectors)
		result.ExpiresAt = workload.CreatedAt.Add(workload.TTL)
		
		// Add attestation information
		for _, attestation := range workload.Attestations {
			result.Attestations = append(result.Attestations, attestation.Type)
		}

		// Check workload status
		if workload.Status != WorkloadStatusActive {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Workload status is %s", workload.Status.String()))
			result.TrustLevel = TrustLevelUntrusted
			return result, nil
		}
	} else {
		result.Warnings = append(result.Warnings, "No workload registration found")
		if result.TrustLevel > TrustLevelLow {
			result.TrustLevel = TrustLevelLow
		}
	}

	result.Valid = len(result.Errors) == 0

	s.logger.WithFields(logrus.Fields{
		"spiffe_id":   spiffeIDStr,
		"valid":       result.Valid,
		"trust_level": result.TrustLevel.String(),
		"warnings":    len(result.Warnings),
		"errors":      len(result.Errors),
	}).Debug("SPIFFE ID validation completed")

	return result, nil
}

// GetWorkloadAttestation returns workload attestation data
func (s *DefaultSPIFFEManager) GetWorkloadAttestation(ctx context.Context, workloadID string) (*WorkloadAttestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	workload, exists := s.workloads[workloadID]
	if !exists {
		return nil, fmt.Errorf("workload %s not found", workloadID)
	}

	return workload, nil
}

// RegisterWorkload registers a workload for SPIFFE attestation
func (s *DefaultSPIFFEManager) RegisterWorkload(ctx context.Context, registration *WorkloadRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.WithFields(logrus.Fields{
		"workload_id": registration.WorkloadID,
		"spiffe_id":   registration.SPIFFEID,
		"selectors":   len(registration.Selectors),
	}).Info("Registering workload")

	// Parse SPIFFE ID
	spiffeID, err := spiffeid.FromString(registration.SPIFFEID)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	// Validate trust domain
	if spiffeID.TrustDomain() != s.trustDomain {
		return fmt.Errorf("SPIFFE ID must be in trust domain %s", s.trustDomain.String())
	}

	// Create workload attestation
	workload := &WorkloadAttestation{
		WorkloadID:   registration.WorkloadID,
		SPIFFEID:     spiffeID,
		Selectors:    registration.Selectors,
		Attestations: make([]AttestationEntry, 0),
		TTL:          registration.TTL,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Status:       WorkloadStatusActive,
	}

	// Add federated trust domains
	for _, federatedTD := range registration.FederatesWith {
		if td, err := spiffeid.TrustDomainFromString(federatedTD); err == nil {
			workload.FederatedWith = append(workload.FederatedWith, td)
		}
	}

	// Store workload
	s.workloads[registration.WorkloadID] = workload

	s.logger.WithField("workload_id", registration.WorkloadID).Info("Workload registered successfully")
	return nil
}

// GetTrustDomain returns the trust domain
func (s *DefaultSPIFFEManager) GetTrustDomain() spiffeid.TrustDomain {
	return s.trustDomain
}

// Start starts background services
func (s *DefaultSPIFFEManager) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("SPIFFE manager already running")
	}

	s.logger.Info("Starting SPIFFE manager services")

	// Start SVID rotation service
	if s.config.AutoRotation.Enabled {
		go s.rotationLoop(ctx)
	}

	// Start workload monitoring
	go s.workloadMonitorLoop(ctx)

	s.running = true
	s.logger.Info("SPIFFE manager services started")

	return nil
}

// Stop stops services
func (s *DefaultSPIFFEManager) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Stopping SPIFFE manager")

	close(s.stopCh)

	if s.workloadAPI != nil {
		if err := s.workloadAPI.Close(); err != nil {
			s.logger.WithError(err).Error("Failed to close workload API client")
		}
	}

	s.running = false
	s.logger.Info("SPIFFE manager stopped")

	return nil
}

// needsRotation checks if an X.509 certificate needs rotation
func (s *DefaultSPIFFEManager) needsRotation(cert *x509.Certificate) bool {
	rotateTime := cert.NotAfter.Add(-s.config.AutoRotation.RotateBefore)
	return time.Now().After(rotateTime)
}

// validateSPIFFEPath validates the path component of a SPIFFE ID
func (s *DefaultSPIFFEManager) validateSPIFFEPath(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	if path[0] != '/' {
		return fmt.Errorf("path must start with /")
	}

	// Additional path validation logic can be added here
	return nil
}

// findWorkloadBySpiffeID finds a workload by its SPIFFE ID
func (s *DefaultSPIFFEManager) findWorkloadBySpiffeID(spiffeID spiffeid.ID) *WorkloadAttestation {
	for _, workload := range s.workloads {
		if workload.SPIFFEID.String() == spiffeID.String() {
			return workload
		}
	}
	return nil
}

// extractSelectorsAsStrings converts workload selectors to string array
func (s *DefaultSPIFFEManager) extractSelectorsAsStrings(selectors []WorkloadSelector) []string {
	result := make([]string, len(selectors))
	for i, selector := range selectors {
		result[i] = fmt.Sprintf("%s:%s", selector.Type, selector.Value)
	}
	return result
}

// rotationLoop handles automatic SVID rotation
func (s *DefaultSPIFFEManager) rotationLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.checkAndRotateSVID(ctx); err != nil {
				s.logger.WithError(err).Error("SVID rotation check failed")
			}
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// checkAndRotateSVID checks and rotates SVID if needed
func (s *DefaultSPIFFEManager) checkAndRotateSVID(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.x509SVID == nil {
		return nil
	}

	if s.needsRotation(s.x509SVID.Certificates[0]) {
		newSVID, err := s.workloadAPI.FetchX509SVID(ctx)
		if err != nil {
			return fmt.Errorf("failed to rotate X.509 SVID: %w", err)
		}

		oldExpiry := s.x509SVID.Certificates[0].NotAfter
		s.x509SVID = newSVID

		s.logger.WithFields(logrus.Fields{
			"old_expiry": oldExpiry,
			"new_expiry": newSVID.Certificates[0].NotAfter,
		}).Info("X.509 SVID automatically rotated")
	}

	return nil
}

// workloadMonitorLoop monitors workload status
func (s *DefaultSPIFFEManager) workloadMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.monitorWorkloads()
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// monitorWorkloads monitors workload health and status
func (s *DefaultSPIFFEManager) monitorWorkloads() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for workloadID, workload := range s.workloads {
		// Check TTL expiration
		if workload.CreatedAt.Add(workload.TTL).Before(now) {
			workload.Status = WorkloadStatusInactive
			s.logger.WithField("workload_id", workloadID).Warn("Workload TTL expired")
		}

		// Update last seen
		workload.UpdatedAt = now
	}
}

// GetTLSConfig returns TLS configuration for SPIFFE-authenticated connections
func (s *DefaultSPIFFEManager) GetTLSConfig(ctx context.Context) (*tlsconfig.TLSConfig, error) {
	if !s.initialized {
		return nil, fmt.Errorf("SPIFFE manager not initialized")
	}

	// Create TLS config with SPIFFE authentication
	tlsConfig := tlsconfig.MTLSClientConfig(s.workloadAPI, s.workloadAPI, tlsconfig.AuthorizeAny())
	
	return tlsConfig, nil
}

// CreateWorkloadSVID creates a new SVID for a workload (server-side operation)
func (s *DefaultSPIFFEManager) CreateWorkloadSVID(ctx context.Context, workloadID string, ttl time.Duration) (*WorkloadSVIDResponse, error) {
	workload, exists := s.workloads[workloadID]
	if !exists {
		return nil, fmt.Errorf("workload %s not registered", workloadID)
	}

	// In a real implementation, this would interact with SPIRE Server
	// For demonstration, we'll create a mock response
	response := &WorkloadSVIDResponse{
		WorkloadID: workloadID,
		SPIFFEID:   workload.SPIFFEID.String(),
		TTL:        ttl,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}

	s.logger.WithFields(logrus.Fields{
		"workload_id": workloadID,
		"spiffe_id":   workload.SPIFFEID.String(),
		"ttl":         ttl,
	}).Info("Workload SVID created")

	return response, nil
}

// WorkloadSVIDResponse represents a workload SVID creation response
type WorkloadSVIDResponse struct {
	WorkloadID string    `json:"workload_id"`
	SPIFFEID   string    `json:"spiffe_id"`
	TTL        time.Duration `json:"ttl"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

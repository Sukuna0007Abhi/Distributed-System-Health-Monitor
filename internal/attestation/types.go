package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RATS Framework Components
// Based on Remote ATtestation procedureS (RATS) Architecture RFC 9334

// AttestationRole defines the role in RATS architecture
type AttestationRole string

const (
	RoleAttester           AttestationRole = "attester"
	RoleVerifier           AttestationRole = "verifier"
	RoleRelyingParty       AttestationRole = "relying_party"
	RoleEndorsementAuthority AttestationRole = "endorsement_authority"
)

// EvidenceType defines the type of attestation evidence
type EvidenceType string

const (
	EvidenceTypeTPM         EvidenceType = "tpm_evidence"
	EvidenceTypeTEE         EvidenceType = "tee_evidence"
	EvidenceTypeSoftware    EvidenceType = "software_evidence"
	EvidenceTypeContainer   EvidenceType = "container_evidence"
	EvidenceTypeComposite   EvidenceType = "composite_evidence"
)

// AttestationClaim represents a single attestation claim
type AttestationClaim struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Issuer    string                 `json:"issuer"`
	Subject   string                 `json:"subject"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Claims    map[string]interface{} `json:"claims"`
	Evidence  *Evidence              `json:"evidence,omitempty"`
}

// Evidence represents attestation evidence according to RATS
type Evidence struct {
	ID            string                 `json:"id"`
	Type          EvidenceType           `json:"type"`
	Format        string                 `json:"format"`
	Timestamp     time.Time              `json:"timestamp"`
	Nonce         string                 `json:"nonce"`
	Measurements  []Measurement          `json:"measurements"`
	Endorsements  []Endorsement          `json:"endorsements"`
	ReferenceValues []ReferenceValue     `json:"reference_values"`
	PolicyID      string                 `json:"policy_id"`
	Claims        map[string]interface{} `json:"claims"`
	Raw           []byte                 `json:"raw,omitempty"`
	Signature     *Signature             `json:"signature,omitempty"`
}

// Measurement represents a measurement in attestation evidence
type Measurement struct {
	Index     int               `json:"index"`
	Algorithm string            `json:"algorithm"`
	Value     string            `json:"value"`
	PCR       int               `json:"pcr,omitempty"`
	EventLog  []MeasurementEvent `json:"event_log,omitempty"`
}

// MeasurementEvent represents an event in the measurement log
type MeasurementEvent struct {
	PCR       int    `json:"pcr"`
	Type      string `json:"type"`
	Digest    string `json:"digest"`
	Data      []byte `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// Endorsement represents an endorsement from an authority
type Endorsement struct {
	ID        string    `json:"id"`
	Authority string    `json:"authority"`
	KeyID     string    `json:"key_id"`
	Value     string    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	Signature *Signature `json:"signature"`
}

// ReferenceValue represents expected reference values
type ReferenceValue struct {
	ID          string    `json:"id"`
	Component   string    `json:"component"`
	Algorithm   string    `json:"algorithm"`
	ExpectedValue string  `json:"expected_value"`
	PolicyRef   string    `json:"policy_ref"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidUntil  time.Time `json:"valid_until"`
}

// Signature represents a cryptographic signature
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// AttestationRequest represents a request for attestation
type AttestationRequest struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	RequesterID   string                 `json:"requester_id"`
	TargetID      string                 `json:"target_id"`
	Nonce         string                 `json:"nonce"`
	PolicyID      string                 `json:"policy_id"`
	EvidenceTypes []EvidenceType         `json:"evidence_types"`
	QoSLevel      QoSLevel               `json:"qos_level"`
	Timestamp     time.Time              `json:"timestamp"`
	ExpiryTime    time.Time              `json:"expiry_time"`
	Context       map[string]interface{} `json:"context"`
}

// AttestationResponse represents the response to an attestation request
type AttestationResponse struct {
	ID           string                   `json:"id"`
	RequestID    string                   `json:"request_id"`
	TenantID     string                   `json:"tenant_id"`
	Status       AttestationStatus        `json:"status"`
	Result       AttestationResult        `json:"result"`
	Evidence     []*Evidence              `json:"evidence"`
	Timestamp    time.Time                `json:"timestamp"`
	VerifiedAt   time.Time                `json:"verified_at"`
	ValidUntil   time.Time                `json:"valid_until"`
	Metadata     AttestationMetadata      `json:"metadata"`
	PolicyResult *PolicyEvaluationResult  `json:"policy_result,omitempty"`
	Error        *AttestationError        `json:"error,omitempty"`
}

// AttestationStatus represents the status of an attestation
type AttestationStatus string

const (
	StatusPending    AttestationStatus = "pending"
	StatusInProgress AttestationStatus = "in_progress"
	StatusCompleted  AttestationStatus = "completed"
	StatusFailed     AttestationStatus = "failed"
	StatusExpired    AttestationStatus = "expired"
	StatusRevoked    AttestationStatus = "revoked"
)

// AttestationResult represents the result of attestation verification
type AttestationResult string

const (
	ResultTrusted        AttestationResult = "trusted"
	ResultUntrusted      AttestationResult = "untrusted"
	ResultUnknown        AttestationResult = "unknown"
	ResultInconclusive   AttestationResult = "inconclusive"
	ResultPolicyViolation AttestationResult = "policy_violation"
)

// QoSLevel defines the Quality of Service level for attestation
type QoSLevel string

const (
	QoSHigh   QoSLevel = "high"
	QoSMedium QoSLevel = "medium"
	QoSLow    QoSLevel = "low"
)

// AttestationMetadata contains metadata about the attestation process
type AttestationMetadata struct {
	VerifierID      string                 `json:"verifier_id"`
	ProcessingTime  time.Duration          `json:"processing_time"`
	EvidenceSize    int64                  `json:"evidence_size"`
	PolicyVersion   string                 `json:"policy_version"`
	ComplianceLevel string                 `json:"compliance_level"`
	TrustLevel      float64                `json:"trust_level"`
	Attributes      map[string]interface{} `json:"attributes"`
}

// PolicyEvaluationResult represents the result of policy evaluation
type PolicyEvaluationResult struct {
	PolicyID      string                   `json:"policy_id"`
	Version       string                   `json:"version"`
	Decision      PolicyDecision           `json:"decision"`
	Violations    []PolicyViolation        `json:"violations"`
	Warnings      []PolicyWarning          `json:"warnings"`
	Score         float64                  `json:"score"`
	EvaluatedAt   time.Time                `json:"evaluated_at"`
	Context       map[string]interface{}   `json:"context"`
}

// PolicyDecision represents a policy decision
type PolicyDecision string

const (
	DecisionAllow PolicyDecision = "allow"
	DecisionDeny  PolicyDecision = "deny"
	DecisionWarn  PolicyDecision = "warn"
)

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Rule        string                 `json:"rule"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Evidence    string                 `json:"evidence"`
	Remediation string                 `json:"remediation"`
	Context     map[string]interface{} `json:"context"`
}

// PolicyWarning represents a policy warning
type PolicyWarning struct {
	Rule    string                 `json:"rule"`
	Message string                 `json:"message"`
	Context map[string]interface{} `json:"context"`
}

// AttestationError represents an error in the attestation process
type AttestationError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   string                 `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// AttestationEvent represents an event in the attestation system
type AttestationEvent struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	Type      AttestationEventType   `json:"type"`
	Source    string                 `json:"source"`
	Subject   string                 `json:"subject"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  EventMetadata          `json:"metadata"`
}

// AttestationEventType defines the type of attestation event
type AttestationEventType string

const (
	EventAttestationRequested   AttestationEventType = "attestation_requested"
	EventEvidenceCollected      AttestationEventType = "evidence_collected"
	EventVerificationStarted    AttestationEventType = "verification_started"
	EventVerificationCompleted  AttestationEventType = "verification_completed"
	EventPolicyEvaluated        AttestationEventType = "policy_evaluated"
	EventAttestationCompleted   AttestationEventType = "attestation_completed"
	EventAttestationFailed      AttestationEventType = "attestation_failed"
	EventEvidenceExpired        AttestationEventType = "evidence_expired"
	EventPolicyUpdated          AttestationEventType = "policy_updated"
	EventAnomalyDetected        AttestationEventType = "anomaly_detected"
	EventComplianceViolation    AttestationEventType = "compliance_violation"
	EventTrustLevelChanged      AttestationEventType = "trust_level_changed"
)

// EventMetadata contains metadata for events
type EventMetadata struct {
	Version     string                 `json:"version"`
	Source      string                 `json:"source"`
	Region      string                 `json:"region"`
	Environment string                 `json:"environment"`
	TraceID     string                 `json:"trace_id"`
	SpanID      string                 `json:"span_id"`
	Attributes  map[string]interface{} `json:"attributes"`
}

// Attester interface defines the attestation generation capabilities
type Attester interface {
	// GenerateEvidence generates attestation evidence
	GenerateEvidence(ctx context.Context, req *EvidenceRequest) (*Evidence, error)
	
	// GetCapabilities returns the attester's capabilities
	GetCapabilities() AttesterCapabilities
	
	// ValidateRequest validates an evidence request
	ValidateRequest(req *EvidenceRequest) error
}

// Verifier interface defines the attestation verification capabilities
type Verifier interface {
	// VerifyEvidence verifies attestation evidence
	VerifyEvidence(ctx context.Context, evidence *Evidence, policy *Policy) (*VerificationResult, error)
	
	// GetCapabilities returns the verifier's capabilities
	GetCapabilities() VerifierCapabilities
	
	// ValidateEvidence validates evidence format and structure
	ValidateEvidence(evidence *Evidence) error
}

// RelyingParty interface defines the relying party capabilities
type RelyingParty interface {
	// ProcessAttestationResult processes attestation results
	ProcessAttestationResult(ctx context.Context, result *AttestationResponse) error
	
	// GetTrustPolicy returns the trust policy for decisions
	GetTrustPolicy() *TrustPolicy
	
	// MakeDecision makes a trust decision based on attestation results
	MakeDecision(result *AttestationResponse) (*TrustDecision, error)
}

// EvidenceRequest represents a request for evidence generation
type EvidenceRequest struct {
	ID            string                 `json:"id"`
	RequesterID   string                 `json:"requester_id"`
	EvidenceTypes []EvidenceType         `json:"evidence_types"`
	Nonce         string                 `json:"nonce"`
	Challenge     []byte                 `json:"challenge"`
	PolicyHints   []string               `json:"policy_hints"`
	Context       map[string]interface{} `json:"context"`
	Timestamp     time.Time              `json:"timestamp"`
}

// VerificationResult represents the result of evidence verification
type VerificationResult struct {
	Verified      bool                   `json:"verified"`
	TrustLevel    float64                `json:"trust_level"`
	Violations    []PolicyViolation      `json:"violations"`
	Warnings      []PolicyWarning        `json:"warnings"`
	Metadata      map[string]interface{} `json:"metadata"`
	VerifiedAt    time.Time              `json:"verified_at"`
	ValidUntil    time.Time              `json:"valid_until"`
}

// AttesterCapabilities defines what an attester can provide
type AttesterCapabilities struct {
	SupportedTypes    []EvidenceType `json:"supported_types"`
	HardwareBacked    bool           `json:"hardware_backed"`
	TPMVersion        string         `json:"tpm_version"`
	TEEType           string         `json:"tee_type"`
	SigningCapable    bool           `json:"signing_capable"`
	RealTimeEvidence  bool           `json:"real_time_evidence"`
	BatchEvidence     bool           `json:"batch_evidence"`
}

// VerifierCapabilities defines what a verifier can verify
type VerifierCapabilities struct {
	SupportedTypes     []EvidenceType `json:"supported_types"`
	PolicyEngines      []string       `json:"policy_engines"`
	ComplianceFrameworks []string     `json:"compliance_frameworks"`
	MaxEvidenceSize    int64          `json:"max_evidence_size"`
	ConcurrentVerifications int       `json:"concurrent_verifications"`
}

// Policy represents an attestation policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Rules       []PolicyRule           `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ValidFrom   time.Time              `json:"valid_from"`
	ValidUntil  time.Time              `json:"valid_until"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Condition   string                 `json:"condition"`
	Action      PolicyAction           `json:"action"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyAction defines the action to take when a rule matches
type PolicyAction string

const (
	ActionAllow    PolicyAction = "allow"
	ActionDeny     PolicyAction = "deny"
	ActionWarn     PolicyAction = "warn"
	ActionRequire  PolicyAction = "require"
	ActionLog      PolicyAction = "log"
)

// TrustPolicy represents a trust policy for decision making
type TrustPolicy struct {
	ID               string                 `json:"id"`
	MinTrustLevel    float64                `json:"min_trust_level"`
	RequiredClaims   []string               `json:"required_claims"`
	ForbiddenClaims  []string               `json:"forbidden_claims"`
	MaxAge           time.Duration          `json:"max_age"`
	RequiredIssuers  []string               `json:"required_issuers"`
	ComplianceLevel  string                 `json:"compliance_level"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// TrustDecision represents a trust decision
type TrustDecision struct {
	Decision    PolicyDecision         `json:"decision"`
	Confidence  float64                `json:"confidence"`
	Reasoning   string                 `json:"reasoning"`
	Violations  []PolicyViolation      `json:"violations"`
	Warnings    []PolicyWarning        `json:"warnings"`
	Metadata    map[string]interface{} `json:"metadata"`
	DecidedAt   time.Time              `json:"decided_at"`
}

// Helper functions

// NewAttestationRequest creates a new attestation request
func NewAttestationRequest(tenantID, requesterID, targetID string, evidenceTypes []EvidenceType) *AttestationRequest {
	return &AttestationRequest{
		ID:            uuid.New().String(),
		TenantID:      tenantID,
		RequesterID:   requesterID,
		TargetID:      targetID,
		Nonce:         generateNonce(),
		EvidenceTypes: evidenceTypes,
		QoSLevel:      QoSMedium,
		Timestamp:     time.Now(),
		ExpiryTime:    time.Now().Add(5 * time.Minute),
		Context:       make(map[string]interface{}),
	}
}

// NewEvidence creates a new evidence instance
func NewEvidence(evidenceType EvidenceType) *Evidence {
	return &Evidence{
		ID:            uuid.New().String(),
		Type:          evidenceType,
		Timestamp:     time.Now(),
		Nonce:         generateNonce(),
		Measurements:  make([]Measurement, 0),
		Endorsements:  make([]Endorsement, 0),
		ReferenceValues: make([]ReferenceValue, 0),
		Claims:        make(map[string]interface{}),
	}
}

// NewAttestationEvent creates a new attestation event
func NewAttestationEvent(tenantID string, eventType AttestationEventType, source, subject string) *AttestationEvent {
	return &AttestationEvent{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Type:      eventType,
		Source:    source,
		Subject:   subject,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
		Metadata: EventMetadata{
			Version: "1.0",
			Attributes: make(map[string]interface{}),
		},
	}
}

// generateNonce generates a cryptographic nonce
func generateNonce() string {
	nonce := uuid.New().String() + fmt.Sprintf("%d", time.Now().UnixNano())
	hash := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(hash[:])
}

// ValidateAttestationRequest validates an attestation request
func ValidateAttestationRequest(req *AttestationRequest) error {
	if req.ID == "" {
		return fmt.Errorf("request ID is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if req.RequesterID == "" {
		return fmt.Errorf("requester ID is required")
	}
	if req.TargetID == "" {
		return fmt.Errorf("target ID is required")
	}
	if len(req.EvidenceTypes) == 0 {
		return fmt.Errorf("at least one evidence type is required")
	}
	if req.ExpiryTime.Before(time.Now()) {
		return fmt.Errorf("request has already expired")
	}
	return nil
}

// ValidateEvidence validates evidence structure
func ValidateEvidence(evidence *Evidence) error {
	if evidence.ID == "" {
		return fmt.Errorf("evidence ID is required")
	}
	if evidence.Type == "" {
		return fmt.Errorf("evidence type is required")
	}
	if evidence.Timestamp.IsZero() {
		return fmt.Errorf("evidence timestamp is required")
	}
	if len(evidence.Measurements) == 0 {
		return fmt.Errorf("at least one measurement is required")
	}
	return nil
}

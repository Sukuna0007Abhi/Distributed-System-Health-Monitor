package hardware

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HardwareAttestor defines the interface for hardware-backed attestation
type HardwareAttestor interface {
	// Initialize the hardware attestation system
	Initialize(ctx context.Context) error
	
	// Generate attestation evidence for a given nonce
	GenerateAttestation(ctx context.Context, nonce []byte) (*AttestationEvidence, error)
	
	// Verify attestation evidence
	VerifyAttestation(ctx context.Context, evidence *AttestationEvidence) (*VerificationResult, error)
	
	// Get platform information
	GetPlatformInfo() *PlatformInfo
	
	// Get attestation capabilities
	GetCapabilities() *AttestationCapabilities
	
	// Close and cleanup resources
	Close() error
}

// AttestationEvidence represents hardware attestation evidence
type AttestationEvidence struct {
	// Platform information
	Platform     *PlatformInfo `json:"platform"`
	
	// Attestation data
	Quote        []byte        `json:"quote"`         // TPM quote or equivalent
	Signature    []byte        `json:"signature"`     // Digital signature
	Certificate  []byte        `json:"certificate"`   // Attestation certificate
	
	// Measurements
	PCRValues    map[int][]byte `json:"pcr_values"`   // Platform Configuration Register values
	EventLog     []byte         `json:"event_log"`    // Measured boot event log
	
	// Metadata
	Nonce        []byte         `json:"nonce"`        // Challenge nonce
	Timestamp    time.Time      `json:"timestamp"`    // Attestation timestamp
	AttestorID   string         `json:"attestor_id"`  // Unique attestor identifier
	
	// Additional claims
	Claims       map[string]interface{} `json:"claims"`
}

// PlatformInfo contains information about the hardware platform
type PlatformInfo struct {
	Vendor       string            `json:"vendor"`       // e.g., "Intel", "AMD", "ARM"
	Model        string            `json:"model"`        // CPU model
	Architecture string            `json:"architecture"` // e.g., "x86_64", "aarch64"
	
	// Security features
	TPMVersion   string            `json:"tpm_version"`  // TPM version (1.2, 2.0)
	TEEType      string            `json:"tee_type"`     // TXT, SVM, TrustZone, etc.
	SecureBoot   bool              `json:"secure_boot"`  // Secure boot status
	MeasuredBoot bool              `json:"measured_boot"`// Measured boot status
	
	// Cloud platform specifics
	CloudProvider string           `json:"cloud_provider,omitempty"` // AWS, Azure, GCP
	InstanceType  string           `json:"instance_type,omitempty"`  // Instance type
	Region        string           `json:"region,omitempty"`         // Cloud region
	
	// Additional metadata
	Metadata     map[string]string `json:"metadata"`
}

// VerificationResult represents the result of attestation verification
type VerificationResult struct {
	Valid        bool              `json:"valid"`
	TrustLevel   TrustLevel        `json:"trust_level"`
	Measurements map[string]bool   `json:"measurements"` // PCR validation results
	Policies     []PolicyResult    `json:"policies"`     // Policy evaluation results
	Warnings     []string          `json:"warnings"`
	Errors       []string          `json:"errors"`
	Timestamp    time.Time         `json:"timestamp"`
	
	// Detailed analysis
	BootChain    *BootChainAnalysis `json:"boot_chain,omitempty"`
	Configuration *ConfigAnalysis   `json:"configuration,omitempty"`
}

// TrustLevel represents the level of trust in the attestation
type TrustLevel int

const (
	TrustLevelUntrusted TrustLevel = iota
	TrustLevelPartial
	TrustLevelTrusted
	TrustLevelHighlyTrusted
)

func (t TrustLevel) String() string {
	switch t {
	case TrustLevelUntrusted:
		return "untrusted"
	case TrustLevelPartial:
		return "partial"
	case TrustLevelTrusted:
		return "trusted"
	case TrustLevelHighlyTrusted:
		return "highly_trusted"
	default:
		return "unknown"
	}
}

// PolicyResult represents the result of a policy evaluation
type PolicyResult struct {
	PolicyID   string    `json:"policy_id"`
	Name       string    `json:"name"`
	Passed     bool      `json:"passed"`
	Message    string    `json:"message"`
	Severity   string    `json:"severity"`
	Timestamp  time.Time `json:"timestamp"`
}

// BootChainAnalysis provides analysis of the boot chain
type BootChainAnalysis struct {
	ValidBootloader bool     `json:"valid_bootloader"`
	ValidKernel     bool     `json:"valid_kernel"`
	ValidInitrd     bool     `json:"valid_initrd"`
	Compromised     bool     `json:"compromised"`
	Issues          []string `json:"issues"`
}

// ConfigAnalysis provides analysis of system configuration
type ConfigAnalysis struct {
	SecureConfig    bool     `json:"secure_config"`
	KnownVulns      []string `json:"known_vulnerabilities"`
	Recommendations []string `json:"recommendations"`
}

// AttestationCapabilities describes the attestation capabilities
type AttestationCapabilities struct {
	TPMSupport      bool     `json:"tpm_support"`
	TEESupport      bool     `json:"tee_support"`
	RemoteAttest    bool     `json:"remote_attestation"`
	SealingSupport  bool     `json:"sealing_support"`
	
	// Supported algorithms
	HashAlgorithms  []string `json:"hash_algorithms"`
	SignAlgorithms  []string `json:"sign_algorithms"`
	
	// Platform specific
	Features        []string `json:"features"`
}

// TPMAttestor implements hardware attestation using TPM 2.0
type TPMAttestor struct {
	mu           sync.RWMutex
	logger       *logrus.Logger
	config       *TPMConfig
	
	// TPM connection
	tpmPath      string
	initialized  bool
	
	// Attestation keys
	attestKey    *rsa.PrivateKey
	attestCert   *x509.Certificate
	
	// Platform info
	platformInfo *PlatformInfo
	capabilities *AttestationCapabilities
	
	// PCR banks
	pcrBanks     map[string][]int // algorithm -> PCR indices
	
	// Event log
	eventLog     []MeasurementEvent
}

// TPMConfig configures the TPM attestor
type TPMConfig struct {
	TPMPath         string            `yaml:"tpm_path" json:"tmp_path"`
	UseSimulator    bool              `yaml:"use_simulator" json:"use_simulator"`
	AttestKeyPath   string            `yaml:"attest_key_path" json:"attest_key_path"`
	AttestCertPath  string            `yaml:"attest_cert_path" json:"attest_cert_path"`
	PCRSelection    []int             `yaml:"pcr_selection" json:"pcr_selection"`
	HashAlgorithm   string            `yaml:"hash_algorithm" json:"hash_algorithm"`
	
	// Policy configuration
	PolicyPaths     []string          `yaml:"policy_paths" json:"policy_paths"`
	TrustedRoots    []string          `yaml:"trusted_roots" json:"trusted_roots"`
	
	// Cloud-specific settings
	CloudProvider   string            `yaml:"cloud_provider" json:"cloud_provider"`
	InstanceMetadata map[string]string `yaml:"instance_metadata" json:"instance_metadata"`
}

// MeasurementEvent represents a measured boot event
type MeasurementEvent struct {
	PCRIndex    int       `json:"pcr_index"`
	EventType   string    `json:"event_type"`
	Digest      []byte    `json:"digest"`
	Data        []byte    `json:"data"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewTPMAttestor creates a new TPM-based hardware attestor
func NewTPMAttestor(config *TPMConfig, logger *logrus.Logger) *TPMAttestor {
	if config == nil {
		config = &TPMConfig{
			TPMPath:       "/dev/tpm0",
			UseSimulator:  false,
			PCRSelection:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			HashAlgorithm: "SHA256",
		}
	}

	return &TPMAttestor{
		logger:    logger,
		config:    config,
		tpmPath:   config.TPMPath,
		pcrBanks:  make(map[string][]int),
		eventLog:  make([]MeasurementEvent, 0),
	}
}

// Initialize initializes the TPM attestor
func (t *TPMAttestor) Initialize(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.logger.Info("Initializing TPM attestor")

	// Initialize platform info
	if err := t.initializePlatformInfo(); err != nil {
		return fmt.Errorf("failed to initialize platform info: %w", err)
	}

	// Initialize capabilities
	if err := t.initializeCapabilities(); err != nil {
		return fmt.Errorf("failed to initialize capabilities: %w", err)
	}

	// Load or generate attestation key
	if err := t.initializeAttestationKey(); err != nil {
		return fmt.Errorf("failed to initialize attestation key: %w", err)
	}

	// Initialize PCR banks
	if err := t.initializePCRBanks(); err != nil {
		return fmt.Errorf("failed to initialize PCR banks: %w", err)
	}

	// Load event log
	if err := t.loadEventLog(); err != nil {
		t.logger.WithError(err).Warn("Failed to load event log")
	}

	t.initialized = true
	t.logger.Info("TPM attestor initialized successfully")

	return nil
}

// GenerateAttestation generates attestation evidence
func (t *TPMAttestor) GenerateAttestation(ctx context.Context, nonce []byte) (*AttestationEvidence, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.initialized {
		return nil, fmt.Errorf("TPM attestor not initialized")
	}

	t.logger.WithField("nonce_len", len(nonce)).Debug("Generating attestation")

	// Read current PCR values
	pcrValues, err := t.readPCRValues()
	if err != nil {
		return nil, fmt.Errorf("failed to read PCR values: %w", err)
	}

	// Generate quote
	quote, err := t.generateQuote(nonce, pcrValues)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quote: %w", err)
	}

	// Sign the quote
	signature, err := t.signQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to sign quote: %w", err)
	}

	// Marshal certificate
	certBytes, err := x509.MarshalCertificate(t.attestCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	// Serialize event log
	eventLogBytes, err := t.serializeEventLog()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize event log: %w", err)
	}

	evidence := &AttestationEvidence{
		Platform:    t.platformInfo,
		Quote:       quote,
		Signature:   signature,
		Certificate: certBytes,
		PCRValues:   pcrValues,
		EventLog:    eventLogBytes,
		Nonce:       nonce,
		Timestamp:   time.Now(),
		AttestorID:  t.generateAttestorID(),
		Claims:      make(map[string]interface{}),
	}

	// Add additional claims
	evidence.Claims["tpm_version"] = t.platformInfo.TPMVersion
	evidence.Claims["secure_boot"] = t.platformInfo.SecureBoot
	evidence.Claims["measured_boot"] = t.platformInfo.MeasuredBoot

	t.logger.Debug("Attestation generated successfully")
	return evidence, nil
}

// VerifyAttestation verifies attestation evidence
func (t *TPMAttestor) VerifyAttestation(ctx context.Context, evidence *AttestationEvidence) (*VerificationResult, error) {
	t.logger.Debug("Verifying attestation evidence")

	result := &VerificationResult{
		Measurements: make(map[string]bool),
		Policies:     make([]PolicyResult, 0),
		Warnings:     make([]string, 0),
		Errors:       make([]string, 0),
		Timestamp:    time.Now(),
	}

	// Verify certificate chain
	if err := t.verifyCertificate(evidence.Certificate); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Certificate verification failed: %v", err))
	}

	// Verify signature
	if err := t.verifySignature(evidence.Quote, evidence.Signature, evidence.Certificate); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature verification failed: %v", err))
	}

	// Verify nonce freshness
	if err := t.verifyNonce(evidence.Nonce, evidence.Timestamp); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Nonce verification warning: %v", err))
	}

	// Verify PCR values
	pcrResults := t.verifyPCRValues(evidence.PCRValues)
	for pcr, valid := range pcrResults {
		result.Measurements[fmt.Sprintf("PCR%s", pcr)] = valid
		if !valid {
			result.Errors = append(result.Errors, fmt.Sprintf("PCR %s verification failed", pcr))
		}
	}

	// Analyze boot chain
	if evidence.EventLog != nil {
		bootAnalysis, err := t.analyzeBootChain(evidence.EventLog)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Boot chain analysis failed: %v", err))
		} else {
			result.BootChain = bootAnalysis
			if bootAnalysis.Compromised {
				result.Errors = append(result.Errors, "Boot chain appears compromised")
			}
		}
	}

	// Evaluate policies
	policyResults, err := t.evaluatePolicies(evidence)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Policy evaluation failed: %v", err))
	} else {
		result.Policies = policyResults
		for _, policy := range policyResults {
			if !policy.Passed && policy.Severity == "error" {
				result.Errors = append(result.Errors, fmt.Sprintf("Policy %s failed: %s", policy.Name, policy.Message))
			}
		}
	}

	// Determine overall validity and trust level
	result.Valid = len(result.Errors) == 0
	result.TrustLevel = t.calculateTrustLevel(result)

	t.logger.WithFields(logrus.Fields{
		"valid":       result.Valid,
		"trust_level": result.TrustLevel.String(),
		"errors":      len(result.Errors),
		"warnings":    len(result.Warnings),
	}).Debug("Attestation verification completed")

	return result, nil
}

// GetPlatformInfo returns platform information
func (t *TPMAttestor) GetPlatformInfo() *PlatformInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.platformInfo
}

// GetCapabilities returns attestation capabilities
func (t *TPMAttestor) GetCapabilities() *AttestationCapabilities {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.capabilities
}

// Close closes the TPM attestor
func (t *TPMAttestor) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.initialized = false
	t.logger.Info("TPM attestor closed")
	return nil
}

// initializePlatformInfo initializes platform information
func (t *TPMAttestor) initializePlatformInfo() error {
	t.platformInfo = &PlatformInfo{
		Vendor:       "Generic", // Would detect actual vendor
		Model:        "Unknown",
		Architecture: "x86_64",  // Would detect actual architecture
		TPMVersion:   "2.0",
		TEEType:      "TXT",     // Would detect Intel TXT, AMD SVM, etc.
		SecureBoot:   true,      // Would check actual secure boot status
		MeasuredBoot: true,      // Would check actual measured boot status
		Metadata:     make(map[string]string),
	}

	// Add cloud-specific information if configured
	if t.config.CloudProvider != "" {
		t.platformInfo.CloudProvider = t.config.CloudProvider
		for key, value := range t.config.InstanceMetadata {
			t.platformInfo.Metadata[key] = value
		}
	}

	return nil
}

// initializeCapabilities initializes attestation capabilities
func (t *TPMAttestor) initializeCapabilities() error {
	t.capabilities = &AttestationCapabilities{
		TPMSupport:     true,
		TEESupport:     true,
		RemoteAttest:   true,
		SealingSupport: true,
		HashAlgorithms: []string{"SHA1", "SHA256", "SHA384", "SHA512"},
		SignAlgorithms: []string{"RSA-2048", "ECC-P256"},
		Features:       []string{"TPM2.0", "TXT", "SRTM", "DRTM"},
	}

	return nil
}

// initializeAttestationKey loads or generates attestation key
func (t *TPMAttestor) initializeAttestationKey() error {
	// For this implementation, we'll generate a mock key
	// In a real implementation, this would interact with the TPM
	var err error
	t.attestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate attestation key: %w", err)
	}

	// Generate a self-signed certificate for demonstration
	t.attestCert, err = t.generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate attestation certificate: %w", err)
	}

	return nil
}

// initializePCRBanks initializes PCR banks
func (t *TPMAttestor) initializePCRBanks() error {
	// Initialize SHA256 PCR bank
	t.pcrBanks["SHA256"] = t.config.PCRSelection
	
	return nil
}

// loadEventLog loads the measured boot event log
func (t *TPMAttestor) loadEventLog() error {
	// Mock event log entries
	t.eventLog = []MeasurementEvent{
		{
			PCRIndex:    0,
			EventType:   "EV_SEPARATOR",
			Digest:      make([]byte, 32),
			Data:        []byte("BIOS"),
			Description: "BIOS measurement",
			Timestamp:   time.Now().Add(-time.Hour),
		},
		{
			PCRIndex:    4,
			EventType:   "EV_IPL",
			Digest:      make([]byte, 32),
			Data:        []byte("GRUB"),
			Description: "Bootloader measurement",
			Timestamp:   time.Now().Add(-30 * time.Minute),
		},
		{
			PCRIndex:    5,
			EventType:   "EV_IPL_PARTITION_DATA",
			Digest:      make([]byte, 32),
			Data:        []byte("KERNEL"),
			Description: "Kernel measurement",
			Timestamp:   time.Now().Add(-15 * time.Minute),
		},
	}

	return nil
}

// readPCRValues reads current PCR values
func (t *TPMAttestor) readPCRValues() (map[int][]byte, error) {
	pcrValues := make(map[int][]byte)

	// Mock PCR values - in real implementation, would read from TPM
	for _, pcr := range t.config.PCRSelection {
		hash := sha256.Sum256([]byte(fmt.Sprintf("mock-pcr-%d", pcr)))
		pcrValues[pcr] = hash[:]
	}

	return pcrValues, nil
}

// generateQuote generates a TPM quote
func (t *TPMAttestor) generateQuote(nonce []byte, pcrValues map[int][]byte) ([]byte, error) {
	// Create quote structure
	quote := struct {
		Nonce     []byte         `json:"nonce"`
		PCRValues map[int][]byte `json:"pcr_values"`
		Timestamp time.Time      `json:"timestamp"`
	}{
		Nonce:     nonce,
		PCRValues: pcrValues,
		Timestamp: time.Now(),
	}

	return json.Marshal(quote)
}

// signQuote signs the quote with the attestation key
func (t *TPMAttestor) signQuote(quote []byte) ([]byte, error) {
	hash := sha256.Sum256(quote)
	return rsa.SignPKCS1v15(rand.Reader, t.attestKey, crypto.SHA256, hash[:])
}

// generateAttestorID generates a unique attestor identifier
func (t *TPMAttestor) generateAttestorID() string {
	// In a real implementation, this would be derived from TPM endorsement key
	return base64.StdEncoding.EncodeToString([]byte("mock-attestor-id"))
}

// serializeEventLog serializes the event log
func (t *TPMAttestor) serializeEventLog() ([]byte, error) {
	return json.Marshal(t.eventLog)
}

// generateSelfSignedCert generates a self-signed certificate
func (t *TPMAttestor) generateSelfSignedCert() (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "TPM Attestation Key",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &t.attestKey.PublicKey, t.attestKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// verifyCertificate verifies the attestation certificate
func (t *TPMAttestor) verifyCertificate(certBytes []byte) error {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is not valid for current time")
	}

	// Additional certificate validation would go here
	// such as checking against trusted roots, CRL, etc.

	return nil
}

// verifySignature verifies the quote signature
func (t *TPMAttestor) verifySignature(quote, signature, certBytes []byte) error {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain RSA public key")
	}

	hash := sha256.Sum256(quote)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

// verifyNonce verifies nonce freshness
func (t *TPMAttestor) verifyNonce(nonce []byte, timestamp time.Time) error {
	// Check timestamp freshness (within last 5 minutes)
	if time.Since(timestamp) > 5*time.Minute {
		return fmt.Errorf("attestation timestamp too old")
	}

	// Additional nonce verification logic would go here
	return nil
}

// verifyPCRValues verifies PCR values against expected values
func (t *TPMAttestor) verifyPCRValues(pcrValues map[int][]byte) map[string]bool {
	results := make(map[string]bool)

	for pcr, value := range pcrValues {
		// In a real implementation, this would check against known good values
		// For demonstration, we'll consider all PCRs valid
		results[fmt.Sprintf("%d", pcr)] = len(value) == 32 // SHA256 hash length
	}

	return results
}

// analyzeBootChain analyzes the boot chain from event log
func (t *TPMAttestor) analyzeBootChain(eventLogBytes []byte) (*BootChainAnalysis, error) {
	var events []MeasurementEvent
	if err := json.Unmarshal(eventLogBytes, &events); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event log: %w", err)
	}

	analysis := &BootChainAnalysis{
		ValidBootloader: true,
		ValidKernel:     true,
		ValidInitrd:     true,
		Compromised:     false,
		Issues:          make([]string, 0),
	}

	// Analyze events for signs of compromise
	for _, event := range events {
		// In a real implementation, this would check against known good measurements
		if len(event.Digest) == 0 {
			analysis.Issues = append(analysis.Issues, fmt.Sprintf("Empty digest for event type %s", event.EventType))
		}
	}

	if len(analysis.Issues) > 0 {
		analysis.Compromised = true
	}

	return analysis, nil
}

// evaluatePolicies evaluates attestation policies
func (t *TPMAttestor) evaluatePolicies(evidence *AttestationEvidence) ([]PolicyResult, error) {
	results := make([]PolicyResult, 0)

	// Example policy: Secure boot must be enabled
	secureBootPolicy := PolicyResult{
		PolicyID:  "secure_boot_required",
		Name:      "Secure Boot Required",
		Passed:    evidence.Platform.SecureBoot,
		Severity:  "error",
		Timestamp: time.Now(),
	}
	if secureBootPolicy.Passed {
		secureBootPolicy.Message = "Secure boot is enabled"
	} else {
		secureBootPolicy.Message = "Secure boot is not enabled"
	}
	results = append(results, secureBootPolicy)

	// Example policy: TPM 2.0 required
	tpmPolicy := PolicyResult{
		PolicyID:  "tpm_version_required",
		Name:      "TPM 2.0 Required",
		Passed:    evidence.Platform.TPMVersion == "2.0",
		Severity:  "error",
		Timestamp: time.Now(),
	}
	if tpmPolicy.Passed {
		tpmPolicy.Message = "TPM 2.0 is present"
	} else {
		tpmPolicy.Message = fmt.Sprintf("TPM version %s is not supported", evidence.Platform.TPMVersion)
	}
	results = append(results, tpmPolicy)

	return results, nil
}

// calculateTrustLevel calculates the overall trust level
func (t *TPMAttestor) calculateTrustLevel(result *VerificationResult) TrustLevel {
	if len(result.Errors) > 0 {
		return TrustLevelUntrusted
	}

	// Check measurement validity
	validMeasurements := 0
	totalMeasurements := len(result.Measurements)
	for _, valid := range result.Measurements {
		if valid {
			validMeasurements++
		}
	}

	// Check policy compliance
	passedPolicies := 0
	errorPolicies := 0
	for _, policy := range result.Policies {
		if policy.Passed {
			passedPolicies++
		} else if policy.Severity == "error" {
			errorPolicies++
		}
	}

	// Calculate trust level based on various factors
	if errorPolicies > 0 {
		return TrustLevelUntrusted
	}

	if totalMeasurements > 0 && validMeasurements == totalMeasurements && passedPolicies == len(result.Policies) {
		if len(result.Warnings) == 0 {
			return TrustLevelHighlyTrusted
		}
		return TrustLevelTrusted
	}

	if validMeasurements > totalMeasurements/2 {
		return TrustLevelPartial
	}

	return TrustLevelUntrusted
}

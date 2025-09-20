package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/attestation"
	"github.com/sirupsen/logrus"
)

// NIST800155Plugin implements NIST 800-155 BIOS Integrity Measurement specification
type NIST800155Plugin struct {
	logger       *logrus.Logger
	initialized  bool
	config       map[string]interface{}
	capabilities PolicyPluginCapabilities
}

// NewNIST800155Plugin creates a new NIST 800-155 policy plugin
func NewNIST800155Plugin(logger *logrus.Logger) *NIST800155Plugin {
	return &NIST800155Plugin{
		logger: logger,
		capabilities: PolicyPluginCapabilities{
			SupportedLanguages: []string{"nist-800-155"},
			SupportedFormats:   []string{"json", "yaml"},
			MaxPolicySize:      1024 * 1024, // 1MB
			ConcurrentEvals:    10,
			Features: []string{
				"bios-integrity",
				"secure-boot",
				"measured-boot",
				"pcr-validation",
				"event-log-analysis",
			},
			Metadata: map[string]interface{}{
				"standard": "NIST 800-155",
				"version":  "1.0",
			},
		},
	}
}

// Name returns the plugin name
func (p *NIST800155Plugin) Name() string {
	return "nist-800-155"
}

// Version returns the plugin version
func (p *NIST800155Plugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin
func (p *NIST800155Plugin) Initialize(config map[string]interface{}) error {
	p.config = config
	p.initialized = true
	p.logger.Info("NIST 800-155 plugin initialized")
	return nil
}

// EvaluatePolicy evaluates NIST 800-155 compliance
func (p *NIST800155Plugin) EvaluatePolicy(ctx context.Context, input PolicyInput) (*PolicyOutput, error) {
	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	output := &PolicyOutput{
		Decision:    attestation.DecisionDeny,
		Violations:  make([]attestation.PolicyViolation, 0),
		Warnings:    make([]attestation.PolicyWarning, 0),
		Score:       0.0,
		Metadata:    make(map[string]interface{}),
		EvaluatedAt: time.Now(),
	}

	// Check for TPM evidence
	tpmEvidence := p.findTPMEvidence(input.Evidence)
	if tpmEvidence == nil {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "nist-800-155-tpm-required",
			Severity:    "high",
			Message:     "TPM evidence is required for NIST 800-155 compliance",
			Evidence:    "",
			Remediation: "Ensure TPM is enabled and providing attestation evidence",
		})
		return output, nil
	}

	// Validate BIOS measurements
	if err := p.validateBIOSMeasurements(tpmEvidence, output); err != nil {
		p.logger.WithError(err).Error("Failed to validate BIOS measurements")
	}

	// Validate secure boot
	if err := p.validateSecureBoot(tpmEvidence, output); err != nil {
		p.logger.WithError(err).Error("Failed to validate secure boot")
	}

	// Validate PCR values
	if err := p.validatePCRValues(tpmEvidence, output); err != nil {
		p.logger.WithError(err).Error("Failed to validate PCR values")
	}

	// Validate event log
	if err := p.validateEventLog(tpmEvidence, output); err != nil {
		p.logger.WithError(err).Error("Failed to validate event log")
	}

	// Calculate overall score
	output.Score = p.calculateNISTScore(output)

	// Determine decision
	if len(output.Violations) == 0 && output.Score >= 0.8 {
		output.Decision = attestation.DecisionAllow
	} else if len(output.Violations) == 0 && output.Score >= 0.6 {
		output.Decision = attestation.DecisionWarn
	}

	output.Metadata["nist_800_155_compliant"] = (output.Decision == attestation.DecisionAllow)
	output.Metadata["evaluation_standard"] = "NIST 800-155"

	return output, nil
}

// findTPMEvidence finds TPM evidence in the input
func (p *NIST800155Plugin) findTPMEvidence(evidence []*attestation.Evidence) *attestation.Evidence {
	for _, ev := range evidence {
		if ev.Type == attestation.EvidenceTypeTPM {
			return ev
		}
	}
	return nil
}

// validateBIOSMeasurements validates BIOS integrity measurements
func (p *NIST800155Plugin) validateBIOSMeasurements(evidence *attestation.Evidence, output *PolicyOutput) error {
	// Check for BIOS measurements in PCR 0-7
	requiredPCRs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	foundPCRs := make(map[int]bool)

	for _, measurement := range evidence.Measurements {
		if measurement.PCR >= 0 && measurement.PCR <= 7 {
			foundPCRs[measurement.PCR] = true
			
			// Validate measurement algorithm
			if !p.isValidHashAlgorithm(measurement.Algorithm) {
				output.Violations = append(output.Violations, attestation.PolicyViolation{
					Rule:        "nist-800-155-hash-algorithm",
					Severity:    "medium",
					Message:     fmt.Sprintf("Invalid hash algorithm %s for PCR %d", measurement.Algorithm, measurement.PCR),
					Evidence:    measurement.Value,
					Remediation: "Use SHA-256 or stronger hash algorithm",
				})
			}

			// Validate measurement value format
			if !p.isValidMeasurementValue(measurement.Value, measurement.Algorithm) {
				output.Violations = append(output.Violations, attestation.PolicyViolation{
					Rule:        "nist-800-155-measurement-format",
					Severity:    "high",
					Message:     fmt.Sprintf("Invalid measurement format for PCR %d", measurement.PCR),
					Evidence:    measurement.Value,
					Remediation: "Ensure measurement values are properly formatted hex strings",
				})
			}
		}
	}

	// Check for missing required PCRs
	for _, requiredPCR := range requiredPCRs {
		if !foundPCRs[requiredPCR] {
			output.Violations = append(output.Violations, attestation.PolicyViolation{
				Rule:        "nist-800-155-required-pcr",
				Severity:    "high",
				Message:     fmt.Sprintf("Required PCR %d measurement missing", requiredPCR),
				Evidence:    "",
				Remediation: fmt.Sprintf("Ensure PCR %d is measured during boot process", requiredPCR),
			})
		}
	}

	return nil
}

// validateSecureBoot validates secure boot configuration
func (p *NIST800155Plugin) validateSecureBoot(evidence *attestation.Evidence, output *PolicyOutput) error {
	// Check for secure boot evidence in claims
	if secureBootEnabled, ok := evidence.Claims["secure_boot_enabled"].(bool); ok {
		if !secureBootEnabled {
			output.Violations = append(output.Violations, attestation.PolicyViolation{
				Rule:        "nist-800-155-secure-boot",
				Severity:    "high",
				Message:     "Secure boot is not enabled",
				Evidence:    "secure_boot_enabled: false",
				Remediation: "Enable secure boot in BIOS/UEFI settings",
			})
		}
	} else {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "nist-800-155-secure-boot-unknown",
			Message: "Secure boot status could not be determined",
		})
	}

	return nil
}

// validatePCRValues validates PCR values against known good values
func (p *NIST800155Plugin) validatePCRValues(evidence *attestation.Evidence, output *PolicyOutput) error {
	// Check for reference values
	if len(evidence.ReferenceValues) == 0 {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "nist-800-155-no-reference-values",
			Message: "No reference values provided for PCR validation",
		})
		return nil
	}

	// Validate each measurement against reference values
	for _, measurement := range evidence.Measurements {
		if measurement.PCR >= 0 && measurement.PCR <= 7 {
			if !p.validateAgainstReferenceValue(measurement, evidence.ReferenceValues) {
				output.Violations = append(output.Violations, attestation.PolicyViolation{
					Rule:        "nist-800-155-pcr-mismatch",
					Severity:    "critical",
					Message:     fmt.Sprintf("PCR %d value does not match reference value", measurement.PCR),
					Evidence:    fmt.Sprintf("Expected: %s, Got: %s", p.getReferenceValue(measurement.PCR, evidence.ReferenceValues), measurement.Value),
					Remediation: "Investigate potential tampering or update reference values",
				})
			}
		}
	}

	return nil
}

// validateEventLog validates the TPM event log
func (p *NIST800155Plugin) validateEventLog(evidence *attestation.Evidence, output *PolicyOutput) error {
	eventLogCount := 0
	for _, measurement := range evidence.Measurements {
		eventLogCount += len(measurement.EventLog)
	}

	if eventLogCount == 0 {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "nist-800-155-no-event-log",
			Message: "No event log entries found",
		})
		return nil
	}

	// Validate event log integrity
	for _, measurement := range evidence.Measurements {
		for _, event := range measurement.EventLog {
			if !p.validateEventLogEntry(event) {
				output.Violations = append(output.Violations, attestation.PolicyViolation{
					Rule:        "nist-800-155-event-log-integrity",
					Severity:    "medium",
					Message:     fmt.Sprintf("Invalid event log entry for PCR %d", event.PCR),
					Evidence:    event.Type,
					Remediation: "Verify event log integrity and format",
				})
			}
		}
	}

	return nil
}

// Helper methods

func (p *NIST800155Plugin) isValidHashAlgorithm(algorithm string) bool {
	validAlgorithms := []string{"SHA-1", "SHA-256", "SHA-384", "SHA-512"}
	for _, valid := range validAlgorithms {
		if strings.EqualFold(algorithm, valid) {
			return true
		}
	}
	return false
}

func (p *NIST800155Plugin) isValidMeasurementValue(value, algorithm string) bool {
	// Remove any prefixes or spaces
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	
	// Check if it's a valid hex string
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}

	// Check length based on algorithm
	expectedLengths := map[string]int{
		"SHA-1":   40,  // 20 bytes * 2
		"SHA-256": 64,  // 32 bytes * 2
		"SHA-384": 96,  // 48 bytes * 2
		"SHA-512": 128, // 64 bytes * 2
	}

	if expectedLen, ok := expectedLengths[algorithm]; ok {
		return len(value) == expectedLen
	}

	return false
}

func (p *NIST800155Plugin) validateAgainstReferenceValue(measurement attestation.Measurement, referenceValues []attestation.ReferenceValue) bool {
	for _, ref := range referenceValues {
		if ref.Component == fmt.Sprintf("PCR_%d", measurement.PCR) {
			return strings.EqualFold(measurement.Value, ref.ExpectedValue)
		}
	}
	return false // No reference value found, assume invalid
}

func (p *NIST800155Plugin) getReferenceValue(pcr int, referenceValues []attestation.ReferenceValue) string {
	for _, ref := range referenceValues {
		if ref.Component == fmt.Sprintf("PCR_%d", pcr) {
			return ref.ExpectedValue
		}
	}
	return "not found"
}

func (p *NIST800155Plugin) validateEventLogEntry(event attestation.MeasurementEvent) bool {
	// Basic validation
	if event.PCR < 0 || event.PCR > 23 {
		return false
	}
	if event.Type == "" {
		return false
	}
	if event.Digest == "" {
		return false
	}
	if event.Timestamp.IsZero() {
		return false
	}
	return true
}

func (p *NIST800155Plugin) calculateNISTScore(output *PolicyOutput) float64 {
	baseScore := 1.0
	
	// Deduct for violations
	for _, violation := range output.Violations {
		switch violation.Severity {
		case "critical":
			baseScore -= 0.3
		case "high":
			baseScore -= 0.2
		case "medium":
			baseScore -= 0.1
		case "low":
			baseScore -= 0.05
		}
	}
	
	// Deduct for warnings
	baseScore -= float64(len(output.Warnings)) * 0.02
	
	if baseScore < 0 {
		baseScore = 0
	}
	
	return baseScore
}

// GetCapabilities returns the plugin capabilities
func (p *NIST800155Plugin) GetCapabilities() PolicyPluginCapabilities {
	return p.capabilities
}

// Close closes the plugin
func (p *NIST800155Plugin) Close() error {
	p.initialized = false
	p.logger.Info("NIST 800-155 plugin closed")
	return nil
}

// SLSAPlugin implements SLSA Level 4 supply chain attestation
type SLSAPlugin struct {
	logger       *logrus.Logger
	initialized  bool
	config       map[string]interface{}
	capabilities PolicyPluginCapabilities
}

// NewSLSAPlugin creates a new SLSA policy plugin
func NewSLSAPlugin(logger *logrus.Logger) *SLSAPlugin {
	return &SLSAPlugin{
		logger: logger,
		capabilities: PolicyPluginCapabilities{
			SupportedLanguages: []string{"slsa"},
			SupportedFormats:   []string{"json", "yaml"},
			MaxPolicySize:      512 * 1024, // 512KB
			ConcurrentEvals:    20,
			Features: []string{
				"supply-chain-security",
				"build-integrity",
				"source-integrity",
				"provenance-verification",
				"hermetic-builds",
			},
			Metadata: map[string]interface{}{
				"standard": "SLSA",
				"level":    4,
			},
		},
	}
}

// Name returns the plugin name
func (p *SLSAPlugin) Name() string {
	return "slsa"
}

// Version returns the plugin version
func (p *SLSAPlugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin
func (p *SLSAPlugin) Initialize(config map[string]interface{}) error {
	p.config = config
	p.initialized = true
	p.logger.Info("SLSA plugin initialized")
	return nil
}

// EvaluatePolicy evaluates SLSA compliance
func (p *SLSAPlugin) EvaluatePolicy(ctx context.Context, input PolicyInput) (*PolicyOutput, error) {
	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	output := &PolicyOutput{
		Decision:    attestation.DecisionDeny,
		Violations:  make([]attestation.PolicyViolation, 0),
		Warnings:    make([]attestation.PolicyWarning, 0),
		Score:       0.0,
		Metadata:    make(map[string]interface{}),
		EvaluatedAt: time.Now(),
	}

	// Find software/container evidence
	softwareEvidence := p.findSoftwareEvidence(input.Evidence)
	if softwareEvidence == nil {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "slsa-software-evidence-required",
			Severity:    "high",
			Message:     "Software evidence is required for SLSA compliance",
			Remediation: "Provide software attestation evidence",
		})
		return output, nil
	}

	// Validate build provenance
	p.validateBuildProvenance(softwareEvidence, output)

	// Validate source integrity
	p.validateSourceIntegrity(softwareEvidence, output)

	// Validate hermetic build
	p.validateHermeticBuild(softwareEvidence, output)

	// Validate reproducible build
	p.validateReproducibleBuild(softwareEvidence, output)

	// Calculate SLSA score
	output.Score = p.calculateSLSAScore(output)

	// Determine decision
	if len(output.Violations) == 0 && output.Score >= 0.9 {
		output.Decision = attestation.DecisionAllow
	} else if len(output.Violations) == 0 && output.Score >= 0.7 {
		output.Decision = attestation.DecisionWarn
	}

	output.Metadata["slsa_level"] = p.determineSLSALevel(output)
	output.Metadata["evaluation_standard"] = "SLSA"

	return output, nil
}

func (p *SLSAPlugin) findSoftwareEvidence(evidence []*attestation.Evidence) *attestation.Evidence {
	for _, ev := range evidence {
		if ev.Type == attestation.EvidenceTypeSoftware || ev.Type == attestation.EvidenceTypeContainer {
			return ev
		}
	}
	return nil
}

func (p *SLSAPlugin) validateBuildProvenance(evidence *attestation.Evidence, output *PolicyOutput) {
	if provenance, ok := evidence.Claims["build_provenance"]; !ok || provenance == nil {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "slsa-build-provenance",
			Severity:    "critical",
			Message:     "Build provenance is missing",
			Remediation: "Ensure build system generates and includes provenance",
		})
	}
}

func (p *SLSAPlugin) validateSourceIntegrity(evidence *attestation.Evidence, output *PolicyOutput) {
	if sourceHash, ok := evidence.Claims["source_hash"].(string); !ok || sourceHash == "" {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "slsa-source-integrity",
			Severity:    "high",
			Message:     "Source code integrity hash is missing",
			Remediation: "Include source code hash in attestation",
		})
	}
}

func (p *SLSAPlugin) validateHermeticBuild(evidence *attestation.Evidence, output *PolicyOutput) {
	if hermetic, ok := evidence.Claims["hermetic_build"].(bool); !ok || !hermetic {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "slsa-hermetic-build",
			Severity:    "medium",
			Message:     "Build is not hermetic",
			Remediation: "Use hermetic build environment",
		})
	}
}

func (p *SLSAPlugin) validateReproducibleBuild(evidence *attestation.Evidence, output *PolicyOutput) {
	if reproducible, ok := evidence.Claims["reproducible_build"].(bool); !ok || !reproducible {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "slsa-reproducible-build",
			Message: "Build reproducibility not verified",
		})
	}
}

func (p *SLSAPlugin) calculateSLSAScore(output *PolicyOutput) float64 {
	baseScore := 1.0
	
	for _, violation := range output.Violations {
		switch violation.Severity {
		case "critical":
			baseScore -= 0.4
		case "high":
			baseScore -= 0.3
		case "medium":
			baseScore -= 0.2
		case "low":
			baseScore -= 0.1
		}
	}
	
	baseScore -= float64(len(output.Warnings)) * 0.05
	
	if baseScore < 0 {
		baseScore = 0
	}
	
	return baseScore
}

func (p *SLSAPlugin) determineSLSALevel(output *PolicyOutput) int {
	if output.Score >= 0.9 && len(output.Violations) == 0 {
		return 4
	} else if output.Score >= 0.8 {
		return 3
	} else if output.Score >= 0.6 {
		return 2
	} else if output.Score >= 0.4 {
		return 1
	}
	return 0
}

// GetCapabilities returns the plugin capabilities
func (p *SLSAPlugin) GetCapabilities() PolicyPluginCapabilities {
	return p.capabilities
}

// Close closes the plugin
func (p *SLSAPlugin) Close() error {
	p.initialized = false
	p.logger.Info("SLSA plugin closed")
	return nil
}

// CompliancePlugin implements general compliance checks (SOC2, PCI-DSS, FedRAMP)
type CompliancePlugin struct {
	logger       *logrus.Logger
	initialized  bool
	config       map[string]interface{}
	capabilities PolicyPluginCapabilities
}

// NewCompliancePlugin creates a new compliance policy plugin
func NewCompliancePlugin(logger *logrus.Logger) *CompliancePlugin {
	return &CompliancePlugin{
		logger: logger,
		capabilities: PolicyPluginCapabilities{
			SupportedLanguages: []string{"compliance"},
			SupportedFormats:   []string{"json", "yaml"},
			MaxPolicySize:      2 * 1024 * 1024, // 2MB
			ConcurrentEvals:    15,
			Features: []string{
				"soc2-compliance",
				"pci-dss-compliance",
				"fedramp-compliance",
				"gdpr-compliance",
				"hipaa-compliance",
			},
			Metadata: map[string]interface{}{
				"standards": []string{"SOC2", "PCI-DSS", "FedRAMP", "GDPR", "HIPAA"},
			},
		},
	}
}

// Name returns the plugin name
func (p *CompliancePlugin) Name() string {
	return "compliance"
}

// Version returns the plugin version
func (p *CompliancePlugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin
func (p *CompliancePlugin) Initialize(config map[string]interface{}) error {
	p.config = config
	p.initialized = true
	p.logger.Info("Compliance plugin initialized")
	return nil
}

// EvaluatePolicy evaluates general compliance requirements
func (p *CompliancePlugin) EvaluatePolicy(ctx context.Context, input PolicyInput) (*PolicyOutput, error) {
	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	output := &PolicyOutput{
		Decision:    attestation.DecisionAllow,
		Violations:  make([]attestation.PolicyViolation, 0),
		Warnings:    make([]attestation.PolicyWarning, 0),
		Score:       1.0,
		Metadata:    make(map[string]interface{}),
		EvaluatedAt: time.Now(),
	}

	// Check encryption requirements
	p.validateEncryption(input.Evidence, output)

	// Check access controls
	p.validateAccessControls(input.Evidence, output)

	// Check audit logging
	p.validateAuditLogging(input.Evidence, output)

	// Check data protection
	p.validateDataProtection(input.Evidence, output)

	// Calculate compliance score
	output.Score = p.calculateComplianceScore(output)

	// Determine decision
	if len(output.Violations) > 0 {
		output.Decision = attestation.DecisionDeny
	} else if len(output.Warnings) > 3 {
		output.Decision = attestation.DecisionWarn
	}

	output.Metadata["compliance_frameworks"] = []string{"SOC2", "PCI-DSS", "FedRAMP"}
	output.Metadata["evaluation_standard"] = "Compliance"

	return output, nil
}

func (p *CompliancePlugin) validateEncryption(evidence []*attestation.Evidence, output *PolicyOutput) {
	encryptionFound := false
	for _, ev := range evidence {
		if encrypted, ok := ev.Claims["data_encrypted"].(bool); ok && encrypted {
			encryptionFound = true
			break
		}
	}

	if !encryptionFound {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "compliance-encryption-required",
			Severity:    "high",
			Message:     "Data encryption is required for compliance",
			Remediation: "Enable data encryption at rest and in transit",
		})
	}
}

func (p *CompliancePlugin) validateAccessControls(evidence []*attestation.Evidence, output *PolicyOutput) {
	accessControlsFound := false
	for _, ev := range evidence {
		if ac, ok := ev.Claims["access_controls"].(bool); ok && ac {
			accessControlsFound = true
			break
		}
	}

	if !accessControlsFound {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "compliance-access-controls",
			Message: "Access controls status not verified",
		})
	}
}

func (p *CompliancePlugin) validateAuditLogging(evidence []*attestation.Evidence, output *PolicyOutput) {
	auditLoggingFound := false
	for _, ev := range evidence {
		if audit, ok := ev.Claims["audit_logging"].(bool); ok && audit {
			auditLoggingFound = true
			break
		}
	}

	if !auditLoggingFound {
		output.Violations = append(output.Violations, attestation.PolicyViolation{
			Rule:        "compliance-audit-logging",
			Severity:    "medium",
			Message:     "Audit logging is not enabled",
			Remediation: "Enable comprehensive audit logging",
		})
	}
}

func (p *CompliancePlugin) validateDataProtection(evidence []*attestation.Evidence, output *PolicyOutput) {
	dataProtectionFound := false
	for _, ev := range evidence {
		if dp, ok := ev.Claims["data_protection"].(bool); ok && dp {
			dataProtectionFound = true
			break
		}
	}

	if !dataProtectionFound {
		output.Warnings = append(output.Warnings, attestation.PolicyWarning{
			Rule:    "compliance-data-protection",
			Message: "Data protection measures not verified",
		})
	}
}

func (p *CompliancePlugin) calculateComplianceScore(output *PolicyOutput) float64 {
	baseScore := 1.0
	
	for _, violation := range output.Violations {
		switch violation.Severity {
		case "critical":
			baseScore -= 0.3
		case "high":
			baseScore -= 0.2
		case "medium":
			baseScore -= 0.15
		case "low":
			baseScore -= 0.1
		}
	}
	
	baseScore -= float64(len(output.Warnings)) * 0.05
	
	if baseScore < 0 {
		baseScore = 0
	}
	
	return baseScore
}

// GetCapabilities returns the plugin capabilities
func (p *CompliancePlugin) GetCapabilities() PolicyPluginCapabilities {
	return p.capabilities
}

// Close closes the plugin
func (p *CompliancePlugin) Close() error {
	p.initialized = false
	p.logger.Info("Compliance plugin closed")
	return nil
}

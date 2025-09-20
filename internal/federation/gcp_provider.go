package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

// GCPProvider implements CloudProvider for Google Cloud Platform
type GCPProvider struct {
	logger       *logrus.Logger
	config       *GCPConfig
	computeClient *compute.InstancesClient
	
	providerInfo *ProviderInfo
}

// NewGCPProvider creates a new GCP cloud provider
func NewGCPProvider(config *GCPConfig, logger *logrus.Logger) (*GCPProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("GCP config is required")
	}

	ctx := context.Background()
	var opts []option.ClientOption

	// Add service account key if provided
	if config.ServiceAccountKey != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(config.ServiceAccountKey)))
	}

	// Create compute client
	computeClient, err := compute.NewInstancesRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %w", err)
	}

	provider := &GCPProvider{
		logger:        logger,
		config:        config,
		computeClient: computeClient,
		providerInfo: &ProviderInfo{
			ID:           "gcp-" + config.Region,
			Name:         "Google Cloud Platform",
			Type:         "gcp",
			Region:       config.Region,
			Endpoint:     "https://compute.googleapis.com",
			Version:      "v1",
			Capabilities: []string{"shielded_vm", "confidential_vm", "vtpm", "integrity_monitoring"},
			Metadata: map[string]string{
				"region":     config.Region,
				"project_id": config.ProjectID,
			},
		},
	}

	return provider, nil
}

// GetProviderInfo returns GCP provider information
func (p *GCPProvider) GetProviderInfo() *ProviderInfo {
	return p.providerInfo
}

// PerformAttestation performs GCP-specific attestation
func (p *GCPProvider) PerformAttestation(ctx context.Context, request *AttestationRequest) (*AttestationResponse, error) {
	p.logger.WithFields(logrus.Fields{
		"instance_id": request.InstanceID,
		"policy_id":   request.PolicyID,
	}).Debug("Performing GCP attestation")

	// Get instance metadata
	metadata, err := p.GetCloudMetadata(ctx)
	if err != nil {
		return &AttestationResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to get metadata: %v", err),
		}, nil
	}

	// Check for Shielded VM and Confidential VM features
	shieldedVM, confidentialVM, err := p.checkVMSecurityFeatures(ctx, request.InstanceID)
	if err != nil {
		p.logger.WithError(err).Warn("Failed to check VM security features")
	}

	// Generate attestation document
	attestationDoc, err := p.generateAttestationDocument(ctx, request, metadata, shieldedVM, confidentialVM)
	if err != nil {
		return &AttestationResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to generate attestation: %v", err),
		}, nil
	}

	evidence := &CloudEvidence{
		ProviderType:  "gcp",
		InstanceID:    request.InstanceID,
		Quote:         attestationDoc,
		CloudMetadata: metadata,
	}

	return &AttestationResponse{
		Success:   true,
		Evidence:  evidence,
		Timestamp: time.Now(),
		Expiry:    time.Now().Add(24 * time.Hour),
	}, nil
}

// VerifyEvidence verifies GCP-specific evidence
func (p *GCPProvider) VerifyEvidence(ctx context.Context, evidence *CloudEvidence) (*VerificationResult, error) {
	p.logger.Debug("Verifying GCP evidence")

	result := &VerificationResult{
		Valid:        true,
		TrustScore:   0.0,
		Policies:     make([]PolicyResult, 0),
		Measurements: make(map[string]bool),
		Warnings:     make([]string, 0),
		Errors:       make([]string, 0),
	}

	// Verify evidence structure
	if evidence.ProviderType != "gcp" {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid provider type for GCP evidence")
		return result, nil
	}

	// Parse attestation document
	var attestDoc GCPAttestationDocument
	if err := json.Unmarshal(evidence.Quote, &attestDoc); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse attestation document: %v", err))
		return result, nil
	}

	// Verify instance metadata consistency
	if err := p.verifyInstanceMetadata(evidence.CloudMetadata, &attestDoc); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Instance metadata inconsistency: %v", err))
		result.TrustScore -= 0.1
	}

	// Verify Shielded VM configuration
	if attestDoc.ShieldedVM {
		result.Measurements["shielded_vm"] = true
		result.TrustScore += 0.3
		
		// Additional checks for Shielded VM features
		if attestDoc.VTPMEnabled {
			result.Measurements["vtpm"] = true
			result.TrustScore += 0.2
		}
		
		if attestDoc.IntegrityMonitoring {
			result.Measurements["integrity_monitoring"] = true
			result.TrustScore += 0.1
		}
		
		if attestDoc.SecureBootEnabled {
			result.Measurements["secure_boot"] = true
			result.TrustScore += 0.1
		}
	} else {
		result.Measurements["shielded_vm"] = false
		result.Warnings = append(result.Warnings, "Shielded VM not enabled")
	}

	// Verify Confidential VM configuration
	if attestDoc.ConfidentialVM {
		result.Measurements["confidential_vm"] = true
		result.TrustScore += 0.4
	} else {
		result.Measurements["confidential_vm"] = false
		result.Warnings = append(result.Warnings, "Confidential VM not enabled")
	}

	// Evaluate GCP-specific policies
	policies := p.evaluateGCPPolicies(&attestDoc, evidence.CloudMetadata)
	result.Policies = policies

	for _, policy := range policies {
		if !policy.Passed {
			if policy.Severity == "error" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("Policy %s failed: %s", policy.Name, policy.Message))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Policy %s warning: %s", policy.Name, policy.Message))
				result.TrustScore -= 0.05
			}
		} else {
			result.TrustScore += 0.1
		}
	}

	// Ensure trust score is within bounds
	if result.TrustScore > 1.0 {
		result.TrustScore = 1.0
	}
	if result.TrustScore < 0.0 {
		result.TrustScore = 0.0
	}

	// Final validation
	if len(result.Errors) > 0 {
		result.Valid = false
		result.TrustScore = 0.0
	}

	p.logger.WithFields(logrus.Fields{
		"valid":       result.Valid,
		"trust_score": result.TrustScore,
		"errors":      len(result.Errors),
		"warnings":    len(result.Warnings),
	}).Debug("GCP evidence verification completed")

	return result, nil
}

// GetCloudMetadata retrieves GCP-specific metadata
func (p *GCPProvider) GetCloudMetadata(ctx context.Context) (*CloudMetadata, error) {
	// In a real implementation, this would query the GCP Instance Metadata Service
	// For demonstration, we'll return mock metadata
	metadata := &CloudMetadata{
		Provider:     "gcp",
		Region:       p.config.Region,
		Zone:         p.config.Region + "-a", // Mock zone
		InstanceType: "n2-standard-2",        // Mock machine type
		ImageID:      "projects/ubuntu-os-cloud/global/images/ubuntu-2004-focal-v20210927",
		Tags: map[string]string{
			"environment": "production",
			"service":     "health-monitor",
		},
		GCPMetadata: &GCPMetadata{
			ProjectID:      p.config.ProjectID,
			Zone:           p.config.Region + "-a",
			InstanceID:     "1234567890123456789",
			MachineType:    "n2-standard-2",
			ShieldedVM:     true,
			ConfidentialVM: true,
		},
	}

	return metadata, nil
}

// HealthCheck performs GCP provider health check
func (p *GCPProvider) HealthCheck(ctx context.Context) error {
	// Test GCP API connectivity by attempting to get a non-existent instance
	// This confirms API access without requiring actual instances
	req := &computepb.GetInstanceRequest{
		Project:  p.config.ProjectID,
		Zone:     p.config.Region + "-a",
		Instance: "health-check-test-instance",
	}

	_, err := p.computeClient.Get(ctx, req)
	if err != nil {
		// Expected error for non-existent instance, but confirms API connectivity
		// Only return error if it's not a "not found" error
		if !isNotFoundError(err) {
			return fmt.Errorf("GCP API health check failed: %w", err)
		}
	}

	return nil
}

// GCPAttestationDocument represents GCP attestation document
type GCPAttestationDocument struct {
	ProjectID           string    `json:"project_id"`
	Zone                string    `json:"zone"`
	InstanceID          string    `json:"instance_id"`
	InstanceName        string    `json:"instance_name"`
	MachineType         string    `json:"machine_type"`
	ShieldedVM          bool      `json:"shielded_vm"`
	ConfidentialVM      bool      `json:"confidential_vm"`
	VTPMEnabled         bool      `json:"vtpm_enabled"`
	IntegrityMonitoring bool      `json:"integrity_monitoring"`
	SecureBootEnabled   bool      `json:"secure_boot_enabled"`
	ImageFingerprint    string    `json:"image_fingerprint"`
	Timestamp           time.Time `json:"timestamp"`
	Nonce               []byte    `json:"nonce"`
	
	// GCP-specific attestation fields
	AttestationToken    []byte            `json:"attestation_token,omitempty"`
	VTPMCertificate     []byte            `json:"vtpm_certificate,omitempty"`
	PCRValues           map[string][]byte `json:"pcr_values,omitempty"`
	IntegrityReport     []byte            `json:"integrity_report,omitempty"`
	
	// Confidential VM specific
	SEVSNPAttestation   []byte            `json:"sev_snp_attestation,omitempty"`
	TDXAttestation      []byte            `json:"tdx_attestation,omitempty"`
}

// checkVMSecurityFeatures checks GCP VM security features
func (p *GCPProvider) checkVMSecurityFeatures(ctx context.Context, instanceID string) (bool, bool, error) {
	// In a real implementation, this would query the instance's security features
	// For demonstration, we'll return mock values
	
	req := &computepb.GetInstanceRequest{
		Project:  p.config.ProjectID,
		Zone:     p.config.Region + "-a",
		Instance: instanceID,
	}

	instance, err := p.computeClient.Get(ctx, req)
	if err != nil {
		if isNotFoundError(err) {
			// For demo purposes, assume features are enabled for non-existent instances
			return true, true, nil
		}
		return false, false, fmt.Errorf("failed to get instance: %w", err)
	}

	// Check for Shielded VM
	shieldedVM := false
	if instance.ShieldedInstanceConfig != nil {
		shieldedVM = true
	}

	// Check for Confidential VM
	confidentialVM := false
	if instance.ConfidentialInstanceConfig != nil {
		confidentialVM = *instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	}

	return shieldedVM, confidentialVM, nil
}

// generateAttestationDocument generates GCP attestation document
func (p *GCPProvider) generateAttestationDocument(ctx context.Context, request *AttestationRequest, metadata *CloudMetadata, shieldedVM, confidentialVM bool) ([]byte, error) {
	doc := GCPAttestationDocument{
		ProjectID:           p.config.ProjectID,
		Zone:                metadata.Zone,
		InstanceID:          request.InstanceID,
		InstanceName:        "health-monitor-instance",
		MachineType:         metadata.InstanceType,
		ShieldedVM:          shieldedVM,
		ConfidentialVM:      confidentialVM,
		VTPMEnabled:         shieldedVM, // vTPM is part of Shielded VM
		IntegrityMonitoring: shieldedVM, // Integrity monitoring is part of Shielded VM
		SecureBootEnabled:   shieldedVM, // Secure boot is part of Shielded VM
		ImageFingerprint:    "sha256:1234567890abcdef", // Mock fingerprint
		Timestamp:           time.Now(),
		Nonce:               request.Nonce,
	}

	// If Shielded VM is enabled, add additional attestation data
	if doc.ShieldedVM {
		// Mock vTPM certificate
		doc.VTPMCertificate = make([]byte, 2048)
		
		// Mock PCR values
		doc.PCRValues = map[string][]byte{
			"PCR0":  make([]byte, 32), // SHA256 hash
			"PCR1":  make([]byte, 32),
			"PCR2":  make([]byte, 32),
			"PCR3":  make([]byte, 32),
			"PCR4":  make([]byte, 32),
			"PCR5":  make([]byte, 32),
			"PCR6":  make([]byte, 32),
			"PCR7":  make([]byte, 32),
			"PCR8":  make([]byte, 32),
			"PCR9":  make([]byte, 32),
			"PCR10": make([]byte, 32),
			"PCR11": make([]byte, 32),
			"PCR12": make([]byte, 32),
			"PCR13": make([]byte, 32),
			"PCR14": make([]byte, 32),
			"PCR15": make([]byte, 32),
		}
		
		// Mock integrity monitoring report
		doc.IntegrityReport = make([]byte, 1024)
	}

	// If Confidential VM is enabled, add confidential computing attestation
	if doc.ConfidentialVM {
		// Mock attestation token from GCP Confidential Space
		doc.AttestationToken = make([]byte, 4096)
		
		// Mock SEV-SNP attestation (for AMD processors)
		doc.SEVSNPAttestation = make([]byte, 1200)
		
		// Mock TDX attestation (for Intel processors)
		doc.TDXAttestation = make([]byte, 2048)
	}

	return json.Marshal(doc)
}

// verifyInstanceMetadata verifies instance metadata consistency
func (p *GCPProvider) verifyInstanceMetadata(metadata *CloudMetadata, attestDoc *GCPAttestationDocument) error {
	if metadata.GCPMetadata == nil {
		return fmt.Errorf("GCP metadata is missing")
	}

	if metadata.GCPMetadata.ProjectID != attestDoc.ProjectID {
		return fmt.Errorf("project ID mismatch: metadata=%s, attest=%s", 
			metadata.GCPMetadata.ProjectID, attestDoc.ProjectID)
	}

	if metadata.GCPMetadata.InstanceID != attestDoc.InstanceID {
		return fmt.Errorf("instance ID mismatch: metadata=%s, attest=%s", 
			metadata.GCPMetadata.InstanceID, attestDoc.InstanceID)
	}

	if metadata.GCPMetadata.Zone != attestDoc.Zone {
		return fmt.Errorf("zone mismatch: metadata=%s, attest=%s", 
			metadata.GCPMetadata.Zone, attestDoc.Zone)
	}

	return nil
}

// evaluateGCPPolicies evaluates GCP-specific policies
func (p *GCPProvider) evaluateGCPPolicies(attestDoc *GCPAttestationDocument, metadata *CloudMetadata) []PolicyResult {
	var results []PolicyResult

	// Policy: Shielded VM required
	shieldedVMPolicy := PolicyResult{
		PolicyID:  "gcp_shielded_vm_required",
		Name:      "Shielded VM Required",
		Passed:    attestDoc.ShieldedVM,
		Severity:  "error",
		Timestamp: time.Now(),
	}
	if shieldedVMPolicy.Passed {
		shieldedVMPolicy.Message = "Shielded VM is enabled"
	} else {
		shieldedVMPolicy.Message = "Shielded VM is not enabled - required for enhanced security"
	}
	results = append(results, shieldedVMPolicy)

	// Policy: Confidential VM recommended for sensitive workloads
	confVMPolicy := PolicyResult{
		PolicyID:  "gcp_confidential_vm_recommended",
		Name:      "Confidential VM Recommended",
		Passed:    attestDoc.ConfidentialVM,
		Severity:  "warning",
		Timestamp: time.Now(),
	}
	if confVMPolicy.Passed {
		confVMPolicy.Message = "Confidential VM is enabled"
	} else {
		confVMPolicy.Message = "Confidential VM is not enabled - recommended for sensitive workloads"
	}
	results = append(results, confVMPolicy)

	// Policy: vTPM required
	vtpmPolicy := PolicyResult{
		PolicyID:  "gcp_vtpm_required",
		Name:      "vTPM Required",
		Passed:    attestDoc.VTPMEnabled,
		Severity:  "error",
		Timestamp: time.Now(),
	}
	if vtpmPolicy.Passed {
		vtpmPolicy.Message = "vTPM is enabled"
	} else {
		vtpmPolicy.Message = "vTPM is not enabled - required for hardware-backed attestation"
	}
	results = append(results, vtpmPolicy)

	// Policy: Integrity monitoring required
	integrityPolicy := PolicyResult{
		PolicyID:  "gcp_integrity_monitoring_required",
		Name:      "Integrity Monitoring Required",
		Passed:    attestDoc.IntegrityMonitoring,
		Severity:  "warning",
		Timestamp: time.Now(),
	}
	if integrityPolicy.Passed {
		integrityPolicy.Message = "Integrity monitoring is enabled"
	} else {
		integrityPolicy.Message = "Integrity monitoring is not enabled - recommended for security"
	}
	results = append(results, integrityPolicy)

	// Policy: Secure Boot required
	secureBootPolicy := PolicyResult{
		PolicyID:  "gcp_secure_boot_required",
		Name:      "Secure Boot Required",
		Passed:    attestDoc.SecureBootEnabled,
		Severity:  "error",
		Timestamp: time.Now(),
	}
	if secureBootPolicy.Passed {
		secureBootPolicy.Message = "Secure Boot is enabled"
	} else {
		secureBootPolicy.Message = "Secure Boot is not enabled - critical security requirement"
	}
	results = append(results, secureBootPolicy)

	// Policy: Approved machine type
	machineTypePolicy := PolicyResult{
		PolicyID:  "gcp_approved_machine_type",
		Name:      "Approved Machine Type",
		Passed:    p.isApprovedMachineType(attestDoc.MachineType),
		Severity:  "warning",
		Timestamp: time.Now(),
	}
	if machineTypePolicy.Passed {
		machineTypePolicy.Message = "Machine type is in approved list"
	} else {
		machineTypePolicy.Message = fmt.Sprintf("Machine type %s is not in approved list", attestDoc.MachineType)
	}
	results = append(results, machineTypePolicy)

	return results
}

// isApprovedMachineType checks if machine type is in approved list
func (p *GCPProvider) isApprovedMachineType(machineType string) bool {
	// In a real implementation, this would check against a database or config
	approvedTypes := map[string]bool{
		"n2-standard-2":   true,
		"n2-standard-4":   true,
		"n2-standard-8":   true,
		"n2-standard-16":  true,
		"n2-standard-32":  true,
		"n2d-standard-2":  true,
		"n2d-standard-4":  true,
		"n2d-standard-8":  true,
		"c2-standard-4":   true,
		"c2-standard-8":   true,
		"c2-standard-16":  true,
		"e2-standard-2":   true,
		"e2-standard-4":   true,
		"e2-standard-8":   true,
		"n2-confidential-2":  true, // Confidential VM types
		"n2-confidential-4":  true,
		"n2-confidential-8":  true,
	}
	
	return approvedTypes[machineType]
}

// isNotFoundError checks if the error is a "not found" error
func isNotFoundError(err error) bool {
	// This is a simplified check - in production you'd use proper error type checking
	return err != nil && (err.Error() == "not found" || 
		                   contains(err.Error(), "not found") ||
		                   contains(err.Error(), "404"))
}

// contains checks if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		                           (len(s) > len(substr) && 
		                            findSubstring(s, substr)))
}

// findSubstring is a simple substring search
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

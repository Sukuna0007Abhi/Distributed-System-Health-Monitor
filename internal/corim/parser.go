package corim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
)

// Parser handles parsing of CoRIM files from CBOR format
type Parser struct {
	config    *ParserConfig
	validator *Validator
	metrics   *Metrics
	logger    Logger
}

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// NewParser creates a new CoRIM parser with the given configuration
func NewParser(config *ParserConfig, validator *Validator, metrics *Metrics, logger Logger) *Parser {
	if config == nil {
		config = &ParserConfig{
			MaxFileSize:     10 * 1024 * 1024, // 10MB default
			ValidateOnLoad:  true,
			StrictMode:      false,
			EnableMetrics:   true,
			EnableDebugLogs: false,
		}
	}

	return &Parser{
		config:    config,
		validator: validator,
		metrics:   metrics,
		logger:    logger,
	}
}

// ParseFile parses a CoRIM file from the filesystem
func (p *Parser) ParseFile(ctx context.Context, path string) (*ParseResult, error) {
	start := time.Now()
	
	// Log the parsing attempt
	p.logger.Info("Starting CoRIM file parsing", "file", path)
	
	// Check file existence and size
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		return nil, NewParseError(err, path, 0, "failed to stat file")
	}

	if fileInfo.Size() > p.config.MaxFileSize {
		return nil, NewParseError(ErrFileTooLarge, path, fileInfo.Size(), 
			fmt.Sprintf("file size %d exceeds maximum %d", fileInfo.Size(), p.config.MaxFileSize))
	}

	// Read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, NewParseError(err, path, 0, MsgFileReadFailed)
	}

	// Calculate file checksum
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	// Parse the data
	result, err := p.Parse(ctx, data)
	if err != nil {
		if p.metrics != nil {
			p.metrics.IncParseErrors("file_parse")
		}
		return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
	}

	// Update result with file metadata
	if result.Profile != nil && result.Profile.Metadata != nil {
		result.Profile.Metadata.FilePath = path
		result.Profile.Metadata.FileSize = fileInfo.Size()
		result.Profile.Metadata.Checksum = checksum
	}

	duration := time.Since(start)
	if p.metrics != nil {
		p.metrics.ObserveParseTime(duration.Seconds())
	}

	p.logger.Info("CoRIM file parsing completed", 
		"file", path,
		"duration", duration,
		"profile_id", result.Profile.ID,
		"ref_values", len(result.Profile.RefValues))

	return result, nil
}

// Parse parses CoRIM data from a byte slice
func (p *Parser) Parse(ctx context.Context, data []byte) (*ParseResult, error) {
	start := time.Now()
	
	if len(data) == 0 {
		return nil, NewParseError(ErrInvalidCoRIM, "", 0, "empty data")
	}

	// Parse CBOR data into CoRIM structure
	var unsignedCoRIM corim.UnsignedCorim
	if err := cbor.Unmarshal(data, &unsignedCoRIM); err != nil {
		return nil, NewParseError(err, "", 0, MsgInvalidCBORFormat)
	}

	// Create profile from parsed data
	profile, warnings, err := p.createProfile(&unsignedCoRIM)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	// Validate if configured to do so
	var validationDuration time.Duration
	if p.config.ValidateOnLoad && p.validator != nil {
		validationStart := time.Now()
		
		validationResult := p.validator.Validate(profile)
		if !validationResult.Valid {
			if p.config.StrictMode {
				return nil, fmt.Errorf("%w: validation failed with %d errors", 
					ErrValidationFailed, validationResult.Summary.ErrorCount)
			}
			// In non-strict mode, add validation errors as warnings
			for _, valErr := range validationResult.Errors {
				warnings = append(warnings, fmt.Sprintf("Validation error in %s: %s", valErr.Field, valErr.Message))
			}
		}
		
		validationDuration = time.Since(validationStart)
		
		// Add validation warnings to result warnings
		for _, valWarn := range validationResult.Warnings {
			warnings = append(warnings, fmt.Sprintf("Validation warning in %s: %s", valWarn.Field, valWarn.Message))
		}
	}

	// Extract reference values
	extractionStart := time.Now()
	refValues, refWarnings, err := p.extractReferenceValues(&unsignedCoRIM, profile.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract reference values: %w", err)
	}
	warnings = append(warnings, refWarnings...)
	profile.RefValues = refValues
	extractionDuration := time.Since(extractionStart)

	// Create parse statistics
	parseDuration := time.Since(start)
	statistics := &ParseStatistics{
		TagsProcessed:       len(unsignedCoRIM.Tags),
		RefValuesExtracted:  len(refValues),
		ParseDuration:       parseDuration,
		ValidationDuration:  validationDuration,
		ExtractionDuration:  extractionDuration,
	}

	// Count total measurements
	for _, refValue := range refValues {
		statistics.MeasurementsFound += len(refValue.Measurements)
	}

	result := &ParseResult{
		Profile:    profile,
		Warnings:   warnings,
		Statistics: statistics,
	}

	if p.config.EnableDebugLogs {
		p.logger.Debug("CoRIM parsing completed with details",
			"parse_duration", parseDuration,
			"validation_duration", validationDuration,
			"extraction_duration", extractionDuration,
			"tags_processed", statistics.TagsProcessed,
			"ref_values_extracted", statistics.RefValuesExtracted,
			"measurements_found", statistics.MeasurementsFound,
			"warnings_count", len(warnings))
	}

	return result, nil
}

// createProfile creates a Profile from the parsed UnsignedCorim
func (p *Parser) createProfile(unsignedCoRIM *corim.UnsignedCorim) (*Profile, []string, error) {
	var warnings []string

	// Extract CoRIM ID using the GetID method
	corimID := unsignedCoRIM.GetID()
	if corimID == "" {
		return nil, warnings, NewParseError(ErrInvalidCoRIM, "", 0, "missing CoRIM ID")
	}

	// Create profile metadata
	metadata := &ProfileMetadata{
		Version:     "1.0", // Default version
		Description: fmt.Sprintf("CoRIM profile %s", corimID),
		Author:      "Unknown",
		Tags:        make(map[string]string),
	}

	// Try to extract metadata from CoRIM if available
	if len(unsignedCoRIM.Tags) > 0 {
		metadata.Description = fmt.Sprintf("CoRIM profile with %d tags", len(unsignedCoRIM.Tags))
	}

	profile := &Profile{
		ID:        corimID,
		Name:      corimID, // Use ID as name initially
		LoadTime:  time.Now(),
		CoRIM:     unsignedCoRIM,
		RefValues: make(map[string]*ReferenceValue),
		Metadata:  metadata,
	}

	return profile, warnings, nil
}

// extractReferenceValues extracts reference values from the CoRIM tags
func (p *Parser) extractReferenceValues(unsignedCoRIM *corim.UnsignedCorim, profileID string) (map[string]*ReferenceValue, []string, error) {
	refValues := make(map[string]*ReferenceValue)
	var warnings []string

	// Since Tags are byte slices in the new API, we need to decode them as CoMID
	for i, tag := range unsignedCoRIM.Tags {
		tagID := fmt.Sprintf("%s-tag-%d", profileID, i)
		
		// Try to decode tag as CoMID
		var comidTag comid.Comid
		if err := comidTag.FromCBOR(tag); err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to decode tag %d as CoMID: %v", i, err))
			continue
		}

		tagRefValues, tagWarnings, err := p.extractFromTag(&comidTag, tagID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to extract from tag %s: %v", tagID, err))
			continue
		}
		
		warnings = append(warnings, tagWarnings...)
		
		// Add to main reference values map
		for key, refValue := range tagRefValues {
			refValues[key] = refValue
		}
	}

	return refValues, warnings, nil
}

// extractFromTag extracts reference values from a single CoMID tag
func (p *Parser) extractFromTag(tag *comid.Comid, tagID string) (map[string]*ReferenceValue, []string, error) {
	refValues := make(map[string]*ReferenceValue)
	var warnings []string

	// Extract from triples (reference values)
	if tag.Triples.ReferenceValues != nil {
		for i, triple := range *tag.Triples.ReferenceValues {
			env, envWarnings, err := p.extractEnvironment(triple.Environment)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Failed to extract environment from triple %d: %v", i, err))
				continue
			}
			warnings = append(warnings, envWarnings...)

			measurements, measWarnings, err := p.extractMeasurements(triple.Measurements)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Failed to extract measurements from triple %d: %v", i, err))
				continue
			}
			warnings = append(warnings, measWarnings...)

			// Create reference value key
			key := p.generateReferenceValueKey(env, tagID, i)

			refValue := &ReferenceValue{
				Key:          key,
				Environment:  env,
				Measurements: measurements,
				TagID:        tagID,
				ExtractedAt:  time.Now(),
			}

			refValues[key] = refValue
		}
	}

	return refValues, warnings, nil
}

// extractEnvironment extracts environment information from a CoMID environment
func (p *Parser) extractEnvironment(env comid.Environment) (*EnvironmentIdentifier, []string, error) {
	var warnings []string

	envId := &EnvironmentIdentifier{
		Attributes: make(map[string]string),
	}

	// Extract class information
	if env.Class != nil {
		if env.Class.ClassID != nil {
			envId.Class = env.Class.ClassID.String()
		}
		if envId.Class == "" {
			envId.Class = EnvClassGeneric
			warnings = append(warnings, "Environment class not specified, using generic")
		}
		
		// Extract vendor and model
		if vendor := env.Class.GetVendor(); vendor != "" {
			envId.Vendor = vendor
		}
		if model := env.Class.GetModel(); model != "" {
			envId.Model = model
		}
	}

	// Extract instance information
	if env.Instance != nil {
		if instanceId := env.Instance.String(); instanceId != "" {
			envId.Instance = instanceId
		}
	}

	// Extract group information (can contain vendor/model info)
	if env.Group != nil {
		if groupId := env.Group.String(); groupId != "" {
			envId.Attributes["group"] = groupId
		}
	}

	// Set some defaults for TPM environment
	if envId.Class == EnvClassTPM {
		if envId.Vendor == "" {
			envId.Vendor = "Unknown"
		}
		if envId.Model == "" {
			envId.Model = "TPM2.0"
		}
	}

	return envId, warnings, nil
}

// extractMeasurements extracts measurements from CoMID measurement values
func (p *Parser) extractMeasurements(measurements comid.Measurements) ([]*Measurement, []string, error) {
	var result []*Measurement
	var warnings []string

	// Handle different measurement types
	for i, meas := range measurements {
		measurement, measWarnings, err := p.extractSingleMeasurement(meas, i)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to extract measurement %d: %v", i, err))
			continue
		}
		warnings = append(warnings, measWarnings...)
		result = append(result, measurement)
	}

	return result, warnings, nil
}

// extractSingleMeasurement extracts a single measurement
func (p *Parser) extractSingleMeasurement(meas comid.Measurement, index int) (*Measurement, []string, error) {
	var warnings []string

	measurement := &Measurement{
		Key:      fmt.Sprintf("measurement-%d", index),
		Metadata: make(map[string]string),
	}

	// Extract measurement key (could be PCR index, etc.)
	if meas.Key != nil {
		// Try to extract key as uint (common for PCR indices)
		if keyUint, err := meas.Key.GetKeyUint(); err == nil {
			measurement.Key = fmt.Sprintf("pcr-%d", keyUint)
		} else {
			// Use the type and some representation
			measurement.Key = fmt.Sprintf("key-%s-%d", meas.Key.Type(), index)
		}
	}

	// Extract measurement value and digest from Val field
	// The Val field contains the actual measurement value/digest
	if meas.Val.Digests != nil && len(*meas.Val.Digests) > 0 {
		// Take the first digest entry
		hashEntry := (*meas.Val.Digests)[0]
		measurement.Digest = hashEntry.HashValue
		measurement.Algorithm = p.algorithmFromID(hashEntry.HashAlgID)
	}

	// If we couldn't extract a proper digest, warn but don't fail
	if len(measurement.Digest) == 0 {
		warnings = append(warnings, fmt.Sprintf("No valid digest found for measurement %s", measurement.Key))
	}

	return measurement, warnings, nil
}

// guessAlgorithm guesses the hash algorithm based on digest length
func (p *Parser) guessAlgorithm(digestLength int) string {
	switch digestLength {
	case SHA256Length:
		return AlgorithmSHA256
	case SHA384Length:
		return AlgorithmSHA384
	case SHA512Length:
		return AlgorithmSHA512
	case SHA1Length:
		return AlgorithmSHA1
	default:
		return "unknown"
	}
}

// algorithmFromID maps algorithm IDs to algorithm names
func (p *Parser) algorithmFromID(algID any) string {
	// Common hash algorithm IDs from IANA registry
	switch algID {
	case -16: // SHA-256
		return AlgorithmSHA256
	case -43: // SHA-384
		return AlgorithmSHA384
	case -44: // SHA-512
		return AlgorithmSHA512
	case -7:  // SHA-1 (not recommended)
		return AlgorithmSHA1
	default:
		return fmt.Sprintf("alg-%v", algID)
	}
}

// generateReferenceValueKey generates a unique key for a reference value
func (p *Parser) generateReferenceValueKey(env *EnvironmentIdentifier, tagID string, index int) string {
	return fmt.Sprintf("%s:%s:%s:%d", env.Class, env.Instance, tagID, index)
}

// Validate validates the parsed CoRIM structure (if validator is available)
func (p *Parser) Validate(profile *Profile) (*ValidationResult, error) {
	if p.validator == nil {
		return &ValidationResult{
			Valid: true,
			Summary: &ValidationSummary{
				TotalChecks: 0,
				ErrorCount:  0,
				WarningCount: 0,
			},
		}, nil
	}

	result := p.validator.Validate(profile)
	return &result, nil
}
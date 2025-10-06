package corim

import (
	"fmt"
	"strings"
)

// Validator provides comprehensive validation of CoRIM profiles and their components
type Validator struct {
	logger Logger
}

// NewValidator creates a new CoRIM validator
func NewValidator(logger Logger) *Validator {
	return &Validator{
		logger: logger,
	}
}

// Validate validates a complete CoRIM profile
func (v *Validator) Validate(profile *Profile) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Summary: &ValidationSummary{
			TotalChecks:           0,
			ErrorCount:            0,
			WarningCount:          0,
			TagsValidated:         0,
			MeasurementsValidated: 0,
		},
	}

	if profile == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    "profile",
			Message:  "Profile cannot be nil",
			Code:     ErrCodeEmptyProfile,
			Severity: string(SeverityError),
		})
		result.Summary.ErrorCount++
		return result
	}

	// Validate basic profile structure
	v.validateProfileStructure(profile, &result)

	// Validate CoRIM structure if present
	if profile.CoRIM != nil {
		v.validateCoRIMStructure(profile.CoRIM, &result)
	}

	// Validate reference values
	v.validateReferenceValues(profile.RefValues, &result)

	// Validate metadata
	if profile.Metadata != nil {
		v.validateMetadata(profile.Metadata, &result)
	}

	// Update final validation status
	result.Valid = result.Summary.ErrorCount == 0

	v.logger.Debug("Profile validation completed",
		"profile_id", profile.ID,
		"valid", result.Valid,
		"errors", result.Summary.ErrorCount,
		"warnings", result.Summary.WarningCount,
		"total_checks", result.Summary.TotalChecks)

	return result
}

// ValidateTag validates a single CoMID tag
func (v *Validator) ValidateTag(tag interface{}, tagIndex int) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Summary: &ValidationSummary{
			TotalChecks:   0,
			ErrorCount:    0,
			WarningCount:  0,
			TagsValidated: 1,
		},
	}

	location := fmt.Sprintf("tag[%d]", tagIndex)

	// Basic tag validation would go here
	// Since we're dealing with the veraison/corim types, we'll do basic checks

	if tag == nil {
		v.addError(&result, "tag", ErrCodeMissingID, "Tag cannot be nil", location)
		return result
	}

	result.Summary.TotalChecks++

	return result
}

// ValidateMeasurement validates a single measurement
func (v *Validator) ValidateMeasurement(measurement *Measurement) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Summary: &ValidationSummary{
			TotalChecks:           0,
			ErrorCount:            0,
			WarningCount:          0,
			MeasurementsValidated: 1,
		},
	}

	if measurement == nil {
		v.addError(&result, "measurement", ErrCodeEmptyProfile, "Measurement cannot be nil", "")
		return result
	}

	location := fmt.Sprintf("measurement[%s]", measurement.Key)

	// Validate measurement key
	result.Summary.TotalChecks++
	if measurement.Key == "" {
		v.addError(&result, "measurement.key", ErrCodeMissingID, "Measurement key cannot be empty", location)
	}

	// Validate algorithm
	result.Summary.TotalChecks++
	if measurement.Algorithm == "" {
		v.addWarning(&result, "measurement.algorithm", "MISSING_ALGORITHM", "Measurement algorithm not specified", location)
	} else {
		if !v.isSupportedAlgorithm(measurement.Algorithm) {
			v.addError(&result, "measurement.algorithm", ErrCodeUnsupportedAlgorithm, 
				fmt.Sprintf("Unsupported algorithm: %s", measurement.Algorithm), location)
		}
	}

	// Validate digest
	result.Summary.TotalChecks++
	if len(measurement.Digest) == 0 {
		v.addError(&result, "measurement.digest", ErrCodeMissingID, "Measurement digest cannot be empty", location)
	} else {
		// Validate digest length matches algorithm
		if measurement.Algorithm != "" {
			expectedLength := v.getExpectedDigestLength(measurement.Algorithm)
			if expectedLength > 0 && len(measurement.Digest) != expectedLength {
				v.addError(&result, "measurement.digest", ErrCodeInvalidDigestLength,
					fmt.Sprintf("Digest length %d doesn't match algorithm %s (expected %d bytes)",
						len(measurement.Digest), measurement.Algorithm, expectedLength), location)
			}
		}
	}

	result.Valid = result.Summary.ErrorCount == 0
	return result
}

// validateProfileStructure validates the basic profile structure
func (v *Validator) validateProfileStructure(profile *Profile, result *ValidationResult) {
	// Validate profile ID
	result.Summary.TotalChecks++
	if profile.ID == "" {
		v.addError(result, "profile.id", ErrCodeMissingID, "Profile ID cannot be empty", "profile")
	}

	// Validate profile name
	result.Summary.TotalChecks++
	if profile.Name == "" {
		v.addWarning(result, "profile.name", "MISSING_NAME", "Profile name is empty", "profile")
	}

	// Validate load time
	result.Summary.TotalChecks++
	if profile.LoadTime.IsZero() {
		v.addWarning(result, "profile.load_time", "INVALID_LOAD_TIME", "Profile load time is not set", "profile")
	}
}

// validateCoRIMStructure validates the CoRIM structure
func (v *Validator) validateCoRIMStructure(corim interface{}, result *ValidationResult) {
	if corim == nil {
		return
	}

	// Since we're working with veraison/corim types, we'll do basic validation
	result.Summary.TotalChecks++

	// The actual validation would depend on the specific structure
	// For now, we'll assume it's valid if it exists
	v.logger.Debug("CoRIM structure validation completed")
}

// validateReferenceValues validates all reference values in a profile
func (v *Validator) validateReferenceValues(refValues map[string]*ReferenceValue, result *ValidationResult) {
	if len(refValues) == 0 {
		v.addWarning(result, "reference_values", "EMPTY_REFERENCE_VALUES", 
			"Profile contains no reference values", "profile")
		return
	}

	for key, refValue := range refValues {
		v.validateReferenceValue(refValue, key, result)
	}
}

// validateReferenceValue validates a single reference value
func (v *Validator) validateReferenceValue(refValue *ReferenceValue, key string, result *ValidationResult) {
	location := fmt.Sprintf("reference_value[%s]", key)

	// Validate reference value key
	result.Summary.TotalChecks++
	if refValue.Key == "" {
		v.addError(result, "reference_value.key", ErrCodeMissingID, "Reference value key cannot be empty", location)
	}

	// Validate environment
	result.Summary.TotalChecks++
	if refValue.Environment == nil {
		v.addError(result, "reference_value.environment", ErrCodeMissingEnvironment, 
			"Reference value must have an environment", location)
	} else {
		v.validateEnvironment(refValue.Environment, location, result)
	}

	// Validate measurements
	result.Summary.TotalChecks++
	if len(refValue.Measurements) == 0 {
		v.addWarning(result, "reference_value.measurements", "EMPTY_MEASUREMENTS", 
			"Reference value contains no measurements", location)
	} else {
		for i, measurement := range refValue.Measurements {
			measurementResult := v.ValidateMeasurement(measurement)
			
			// Add measurement validation results to overall result
			for _, err := range measurementResult.Errors {
				err.Location = fmt.Sprintf("%s.measurement[%d]", location, i)
				result.Errors = append(result.Errors, err)
			}
			
			for _, warn := range measurementResult.Warnings {
				warn.Location = fmt.Sprintf("%s.measurement[%d]", location, i)
				result.Warnings = append(result.Warnings, warn)
			}
			
			result.Summary.ErrorCount += measurementResult.Summary.ErrorCount
			result.Summary.WarningCount += measurementResult.Summary.WarningCount
			result.Summary.TotalChecks += measurementResult.Summary.TotalChecks
			result.Summary.MeasurementsValidated += measurementResult.Summary.MeasurementsValidated
		}
	}

	// Validate tag ID
	result.Summary.TotalChecks++
	if refValue.TagID == "" {
		v.addWarning(result, "reference_value.tag_id", "MISSING_TAG_ID", 
			"Reference value has no associated tag ID", location)
	}
}

// validateEnvironment validates an environment identifier
func (v *Validator) validateEnvironment(env *EnvironmentIdentifier, location string, result *ValidationResult) {
	if env == nil {
		v.addError(result, "environment", ErrCodeMissingEnvironment, 
			"Environment identifier cannot be nil", location)
		return
	}

	// Validate environment class
	result.Summary.TotalChecks++
	if env.Class == "" {
		v.addError(result, "environment.class", ErrCodeMissingEnvironment, 
			"Environment class cannot be empty", location)
	} else {
		// Validate known environment classes
		if !v.isValidEnvironmentClass(env.Class) {
			v.addError(result, "environment.class", "INVALID_ENVIRONMENT_CLASS", 
				fmt.Sprintf("Invalid environment class: %s", env.Class), location)
		}
	}

	// For TPM environments, validate additional required fields
	if env.Class == EnvClassTPM {
		result.Summary.TotalChecks++
		if env.Vendor == "" {
			v.addWarning(result, "environment.vendor", "MISSING_VENDOR", 
				"TPM environment should specify vendor", location)
		}
		
		result.Summary.TotalChecks++
		if env.Model == "" {
			v.addWarning(result, "environment.model", "MISSING_MODEL", 
				"TPM environment should specify model", location)
		}
	}
}

// validateMetadata validates profile metadata
func (v *Validator) validateMetadata(metadata *ProfileMetadata, result *ValidationResult) {
	// Validate version
	result.Summary.TotalChecks++
	if metadata.Version == "" {
		v.addWarning(result, "metadata.version", "MISSING_VERSION", "Profile version not specified", "metadata")
	}

	// Validate file size if file path is specified
	if metadata.FilePath != "" {
		result.Summary.TotalChecks++
		if metadata.FileSize <= 0 {
			v.addWarning(result, "metadata.file_size", "INVALID_FILE_SIZE", 
				"File size should be positive when file path is specified", "metadata")
		}
	}

	// Validate checksum format if present
	if metadata.Checksum != "" {
		result.Summary.TotalChecks++
		if !v.isValidChecksumFormat(metadata.Checksum) {
			v.addWarning(result, "metadata.checksum", "INVALID_CHECKSUM_FORMAT", 
				"Checksum format appears invalid", "metadata")
		}
	}
}

// Helper methods

func (v *Validator) addError(result *ValidationResult, field, code, message, location string) {
	result.Errors = append(result.Errors, ValidationError{
		Field:    field,
		Message:  message,
		Code:     code,
		Severity: string(SeverityError),
		Location: location,
	})
	result.Summary.ErrorCount++
	result.Valid = false
}

func (v *Validator) addWarning(result *ValidationResult, field, code, message, location string) {
	result.Warnings = append(result.Warnings, ValidationWarning{
		Field:    field,
		Message:  message,
		Code:     code,
		Location: location,
	})
	result.Summary.WarningCount++
}

func (v *Validator) isSupportedAlgorithm(algorithm string) bool {
	switch strings.ToLower(algorithm) {
	case AlgorithmSHA256, AlgorithmSHA384, AlgorithmSHA512, AlgorithmSHA1:
		return true
	default:
		return false
	}
}

func (v *Validator) getExpectedDigestLength(algorithm string) int {
	switch strings.ToLower(algorithm) {
	case AlgorithmSHA256:
		return SHA256Length
	case AlgorithmSHA384:
		return SHA384Length
	case AlgorithmSHA512:
		return SHA512Length
	case AlgorithmSHA1:
		return SHA1Length
	default:
		return 0 // Unknown algorithm
	}
}

func (v *Validator) isValidEnvironmentClass(class string) bool {
	switch class {
	case EnvClassTPM, EnvClassTEE, EnvClassUEFI, EnvClassGeneric:
		return true
	default:
		return false
	}
}

func (v *Validator) isValidChecksumFormat(checksum string) bool {
	// Basic validation for hex format
	if len(checksum) != 64 { // SHA-256 hex length
		return false
	}
	
	for _, c := range checksum {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	
	return true
}

// ValidateConfig validates CoRIM configuration
func (v *Validator) ValidateConfig(config *CoRIMConfig) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Summary: &ValidationSummary{
			TotalChecks:  0,
			ErrorCount:   0,
			WarningCount: 0,
		},
	}

	if config == nil {
		v.addError(&result, "config", ErrCodeEmptyProfile, "CoRIM configuration cannot be nil", "config")
		return result
	}

	// Validate storage config
	if config.Storage != nil {
		v.validateStorageConfig(config.Storage, &result)
	}

	// Validate parser config
	if config.Parser != nil {
		v.validateParserConfig(config.Parser, &result)
	}

	// Validate profiles path
	result.Summary.TotalChecks++
	if config.ProfilesPath == "" && config.AutoLoad {
		v.addWarning(&result, "config.profiles_path", "MISSING_PROFILES_PATH", 
			"Profiles path not specified but auto-load is enabled", "config")
	}

	result.Valid = result.Summary.ErrorCount == 0
	return result
}

func (v *Validator) validateStorageConfig(config *StoreConfig, result *ValidationResult) {
	// Validate Redis address
	result.Summary.TotalChecks++
	if config.RedisAddr == "" {
		v.addError(result, "storage.redis_addr", "MISSING_REDIS_ADDR", 
			"Redis address is required", "config.storage")
	}

	// Validate key prefix
	result.Summary.TotalChecks++
	if config.KeyPrefix == "" {
		v.addWarning(result, "storage.key_prefix", "MISSING_KEY_PREFIX", 
			"Key prefix not specified, using default", "config.storage")
	}

	// Validate TTL
	result.Summary.TotalChecks++
	if config.TTL <= 0 {
		v.addWarning(result, "storage.ttl", "INVALID_TTL", 
			"TTL should be positive", "config.storage")
	}
}

func (v *Validator) validateParserConfig(config *ParserConfig, result *ValidationResult) {
	// Validate max file size
	result.Summary.TotalChecks++
	if config.MaxFileSize <= 0 {
		v.addWarning(result, "parser.max_file_size", "INVALID_MAX_FILE_SIZE", 
			"Max file size should be positive", "config.parser")
	}
}
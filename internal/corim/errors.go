package corim

import (
	"errors"
	"fmt"
)

// Base errors
var (
	// ErrInvalidCoRIM indicates the CoRIM structure is invalid
	ErrInvalidCoRIM = errors.New("invalid CoRIM structure")
	
	// ErrProfileNotFound indicates a requested profile doesn't exist
	ErrProfileNotFound = errors.New("profile not found")
	
	// ErrParseFailure indicates parsing failed
	ErrParseFailure = errors.New("CoRIM parse failure")
	
	// ErrValidationFailed indicates validation failed
	ErrValidationFailed = errors.New("CoRIM validation failed")
	
	// ErrStorageFailure indicates storage operation failed
	ErrStorageFailure = errors.New("storage operation failed")
	
	// ErrProvisioningFailed indicates provisioning failed
	ErrProvisioningFailed = errors.New("profile provisioning failed")
	
	// ErrConfigurationInvalid indicates configuration is invalid
	ErrConfigurationInvalid = errors.New("invalid configuration")
	
	// ErrConnectionFailed indicates connection to external service failed
	ErrConnectionFailed = errors.New("connection failed")
	
	// ErrFileNotFound indicates the requested file doesn't exist
	ErrFileNotFound = errors.New("file not found")
	
	// ErrFileTooLarge indicates the file exceeds size limits
	ErrFileTooLarge = errors.New("file too large")
	
	// ErrUnsupportedFormat indicates the file format is not supported
	ErrUnsupportedFormat = errors.New("unsupported file format")
	
	// ErrDuplicateProfile indicates a profile with the same ID already exists
	ErrDuplicateProfile = errors.New("duplicate profile ID")
	
	// ErrEmptyProfile indicates the profile contains no useful data
	ErrEmptyProfile = errors.New("empty profile")
	
	// ErrInvalidEnvironment indicates the environment identifier is invalid
	ErrInvalidEnvironment = errors.New("invalid environment identifier")
	
	// ErrInvalidMeasurement indicates a measurement is invalid
	ErrInvalidMeasurement = errors.New("invalid measurement")
	
	// ErrUnsupportedAlgorithm indicates the digest algorithm is not supported
	ErrUnsupportedAlgorithm = errors.New("unsupported digest algorithm")
)

// ParseError wraps parsing-related errors with additional context
type ParseError struct {
	Cause    error
	File     string
	Position int64
	Message  string
}

func (e *ParseError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("parse error in %s at position %d: %s: %v", 
			e.File, e.Position, e.Message, e.Cause)
	}
	return fmt.Sprintf("parse error at position %d: %s: %v", 
		e.Position, e.Message, e.Cause)
}

func (e *ParseError) Unwrap() error {
	return e.Cause
}

// NewParseError creates a new parse error
func NewParseError(cause error, file string, position int64, message string) *ParseError {
	return &ParseError{
		Cause:    cause,
		File:     file,
		Position: position,
		Message:  message,
	}
}

// ValidationError represents a validation error with structured details
type ValidationErrorDetail struct {
	Cause     error
	Field     string
	Value     interface{}
	Code      string
	Message   string
	Location  string
	Severity  ValidationSeverity
}

func (e *ValidationErrorDetail) Error() string {
	return fmt.Sprintf("validation error in %s: %s (code: %s): %v", 
		e.Field, e.Message, e.Code, e.Cause)
}

func (e *ValidationErrorDetail) Unwrap() error {
	return e.Cause
}

// ValidationSeverity indicates the severity of a validation issue
type ValidationSeverity string

const (
	SeverityError   ValidationSeverity = "error"
	SeverityWarning ValidationSeverity = "warning"
	SeverityInfo    ValidationSeverity = "info"
)

// NewValidationError creates a new validation error
func NewValidationError(field, code, message string) *ValidationErrorDetail {
	return &ValidationErrorDetail{
		Cause:    ErrValidationFailed,
		Field:    field,
		Code:     code,
		Message:  message,
		Severity: SeverityError,
	}
}

// StorageError wraps storage-related errors with operation context
type StorageError struct {
	Cause     error
	Operation string
	Key       string
	Message   string
}

func (e *StorageError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("storage error in %s operation for key %s: %s: %v", 
			e.Operation, e.Key, e.Message, e.Cause)
	}
	return fmt.Sprintf("storage error in %s operation: %s: %v", 
		e.Operation, e.Message, e.Cause)
}

func (e *StorageError) Unwrap() error {
	return e.Cause
}

// NewStorageError creates a new storage error
func NewStorageError(cause error, operation, key, message string) *StorageError {
	return &StorageError{
		Cause:     cause,
		Operation: operation,
		Key:       key,
		Message:   message,
	}
}

// ProvisioningError wraps provisioning-related errors
type ProvisioningError struct {
	Cause     error
	ProfileID string
	Stage     string
	Message   string
}

func (e *ProvisioningError) Error() string {
	return fmt.Sprintf("provisioning error for profile %s in %s stage: %s: %v", 
		e.ProfileID, e.Stage, e.Message, e.Cause)
}

func (e *ProvisioningError) Unwrap() error {
	return e.Cause
}

// NewProvisioningError creates a new provisioning error
func NewProvisioningError(cause error, profileID, stage, message string) *ProvisioningError {
	return &ProvisioningError{
		Cause:     cause,
		ProfileID: profileID,
		Stage:     stage,
		Message:   message,
	}
}

// ConfigurationError wraps configuration-related errors
type ConfigurationError struct {
	Cause   error
	Field   string
	Value   interface{}
	Message string
}

func (e *ConfigurationError) Error() string {
	return fmt.Sprintf("configuration error in field %s (value: %v): %s: %v", 
		e.Field, e.Value, e.Message, e.Cause)
}

func (e *ConfigurationError) Unwrap() error {
	return e.Cause
}

// NewConfigurationError creates a new configuration error
func NewConfigurationError(cause error, field string, value interface{}, message string) *ConfigurationError {
	return &ConfigurationError{
		Cause:   cause,
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// Error checking helper functions

// IsParseError checks if an error is a parse error
func IsParseError(err error) bool {
	var parseErr *ParseError
	return errors.As(err, &parseErr)
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	var validationErr *ValidationErrorDetail
	return errors.As(err, &validationErr)
}

// IsStorageError checks if an error is a storage error
func IsStorageError(err error) bool {
	var storageErr *StorageError
	return errors.As(err, &storageErr)
}

// IsProvisioningError checks if an error is a provisioning error
func IsProvisioningError(err error) bool {
	var provisioningErr *ProvisioningError
	return errors.As(err, &provisioningErr)
}

// IsConfigurationError checks if an error is a configuration error
func IsConfigurationError(err error) bool {
	var configErr *ConfigurationError
	return errors.As(err, &configErr)
}

// IsProfileNotFound checks if an error indicates a profile was not found
func IsProfileNotFound(err error) bool {
	return errors.Is(err, ErrProfileNotFound)
}

// IsConnectionError checks if an error is related to connection issues
func IsConnectionError(err error) bool {
	return errors.Is(err, ErrConnectionFailed)
}

// Error message constants for consistent error reporting
const (
	MsgInvalidCBORFormat       = "invalid CBOR format"
	MsgMissingRequiredField    = "missing required field"
	MsgInvalidFieldValue       = "invalid field value"
	MsgUnsupportedVersion      = "unsupported version"
	MsgDigestLengthMismatch    = "digest length doesn't match algorithm"
	MsgEnvironmentNotSpecified = "environment not specified"
	MsgProfileAlreadyExists    = "profile with this ID already exists"
	MsgRedisConnectionFailed   = "failed to connect to Redis"
	MsgFileReadFailed          = "failed to read file"
	MsgFileSizeTooLarge        = "file size exceeds maximum allowed"
	MsgInvalidConfiguration    = "configuration validation failed"
)
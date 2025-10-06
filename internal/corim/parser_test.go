package corim

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock logger for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

// Test data
func createTestProfile() *Profile {
	return &Profile{
		ID:       "test-profile-001",
		Name:     "Test Profile",
		LoadTime: time.Now(),
		Metadata: &ProfileMetadata{
			Version:     "1.0",
			Description: "Test CoRIM Profile",
			Author:      "Test Suite",
		},
		RefValues: map[string]*ReferenceValue{
			"test-key-1": {
				Key: "test-key-1",
				Environment: &EnvironmentIdentifier{
					Class:    EnvClassTPM,
					Instance: "test-instance",
					Vendor:   "TestVendor",
					Model:    "TestModel",
				},
				Measurements: []*Measurement{
					{
						Key:       "pcr-0",
						Algorithm: AlgorithmSHA256,
						Digest:    make([]byte, SHA256Length),
					},
				},
				TagID:       "test-tag-001",
				ExtractedAt: time.Now(),
			},
		},
	}
}

func createTestConfig() *ParserConfig {
	return &ParserConfig{
		MaxFileSize:      1024 * 1024, // 1MB
		ValidateOnLoad:   true,
		StrictMode:       false,
		EnableMetrics:    false,
		EnableDebugLogs:  false,
	}
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "invalid CBOR",
			data:        []byte{0xFF, 0xFF, 0xFF},
			expectError: true,
		},
		{
			name: "valid CoRIM file data",
			data: func() []byte {
				// Load one of our generated CoRIM files for testing
				data, _ := os.ReadFile("../../configs/corim-profiles/example-tpm.cbor")
				return data
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			logger.On("Debug", mock.Anything, mock.Anything).Maybe()
			logger.On("Info", mock.Anything, mock.Anything).Maybe()
			logger.On("Warn", mock.Anything, mock.Anything).Maybe()
			logger.On("Error", mock.Anything, mock.Anything).Maybe()

			validator := NewValidator(logger)
			parser := NewParser(createTestConfig(), validator, nil, logger)

			ctx := context.Background()
			result, err := parser.Parse(ctx, tt.data)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	tests := []struct {
		name     string
		profile  *Profile
		expected bool
	}{
		{
			name:     "nil profile",
			profile:  nil,
			expected: false,
		},
		{
			name: "profile with empty ID",
			profile: &Profile{
				ID:   "",
				Name: "Test",
			},
			expected: false,
		},
		{
			name:     "valid profile",
			profile:  createTestProfile(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			logger.On("Debug", mock.Anything, mock.Anything).Maybe()

			validator := NewValidator(logger)
			result := validator.Validate(tt.profile)

			assert.Equal(t, tt.expected, result.Valid)
		})
	}
}

func TestValidator_ValidateMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		measurement *Measurement
		expected    bool
	}{
		{
			name:        "nil measurement",
			measurement: nil,
			expected:    false,
		},
		{
			name: "measurement with empty key",
			measurement: &Measurement{
				Key:       "",
				Algorithm: AlgorithmSHA256,
				Digest:    make([]byte, SHA256Length),
			},
			expected: false,
		},
		{
			name: "measurement with wrong digest length",
			measurement: &Measurement{
				Key:       "pcr-0",
				Algorithm: AlgorithmSHA256,
				Digest:    make([]byte, 10), // Wrong length
			},
			expected: false,
		},
		{
			name: "valid measurement",
			measurement: &Measurement{
				Key:       "pcr-0",
				Algorithm: AlgorithmSHA256,
				Digest:    make([]byte, SHA256Length),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			logger.On("Debug", mock.Anything, mock.Anything).Maybe()

			validator := NewValidator(logger)
			result := validator.ValidateMeasurement(tt.measurement)

			assert.Equal(t, tt.expected, result.Valid)
		})
	}
}

func TestEnvironmentIdentifier_Validation(t *testing.T) {
	tests := []struct {
		name        string
		envID       *EnvironmentIdentifier
		expectError bool
	}{
		{
			name:        "nil environment",
			envID:       nil,
			expectError: true,
		},
		{
			name: "empty class",
			envID: &EnvironmentIdentifier{
				Class: "",
			},
			expectError: true,
		},
		{
			name: "valid TPM environment",
			envID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
				Vendor:   "TestVendor",
				Model:    "TestModel",
			},
			expectError: false,
		},
		{
			name: "invalid class",
			envID: &EnvironmentIdentifier{
				Class:    "invalid-class",
				Instance: "test-instance",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			logger.On("Debug", mock.Anything, mock.Anything).Maybe()

			validator := NewValidator(logger)
			result := &ValidationResult{
				Valid:    true,
				Errors:   []ValidationError{},
				Warnings: []ValidationWarning{},
				Summary: &ValidationSummary{
					TotalChecks:  0,
					ErrorCount:   0,
					WarningCount: 0,
				},
			}

			validator.validateEnvironment(tt.envID, "test", result)

			if tt.expectError {
				assert.Greater(t, result.Summary.ErrorCount, 0)
			} else {
				assert.Equal(t, 0, result.Summary.ErrorCount)
			}
		})
	}
}

func TestProfileSummary(t *testing.T) {
	profile := createTestProfile()

	summary := &ProfileSummary{
		ID:          profile.ID,
		Name:        profile.Name,
		LoadTime:    profile.LoadTime,
		RefCount:    len(profile.RefValues),
		Metadata:    profile.Metadata,
	}

	assert.Equal(t, profile.ID, summary.ID)
	assert.Equal(t, profile.Name, summary.Name)
	assert.Equal(t, len(profile.RefValues), summary.RefCount)
	assert.Equal(t, profile.Metadata, summary.Metadata)
}

func TestConstants(t *testing.T) {
	// Test algorithm constants
	assert.Equal(t, "sha256", AlgorithmSHA256)
	assert.Equal(t, "sha384", AlgorithmSHA384)
	assert.Equal(t, "sha512", AlgorithmSHA512)
	assert.Equal(t, "sha1", AlgorithmSHA1)

	// Test digest lengths
	assert.Equal(t, 32, SHA256Length)
	assert.Equal(t, 48, SHA384Length)
	assert.Equal(t, 64, SHA512Length)
	assert.Equal(t, 20, SHA1Length)

	// Test environment classes
	assert.Equal(t, "tpm", EnvClassTPM)
	assert.Equal(t, "tee", EnvClassTEE)
	assert.Equal(t, "uefi", EnvClassUEFI)
	assert.Equal(t, "generic", EnvClassGeneric)
}

func TestErrorTypes(t *testing.T) {
	// Test error creation
	parseErr := NewParseError(ErrInvalidCoRIM, "test.cbor", 100, "test error")
	assert.Contains(t, parseErr.Error(), "parse error in test.cbor")
	assert.Contains(t, parseErr.Error(), "at position 100")

	validationErr := NewValidationError("test.field", ErrCodeMissingID, "test message")
	assert.Contains(t, validationErr.Error(), "validation error in test.field")

	storageErr := NewStorageError(ErrStorageFailure, "get", "test-key", "test message")
	assert.Contains(t, storageErr.Error(), "storage error in get operation")

	// Test error type checking
	assert.True(t, IsParseError(parseErr))
	assert.True(t, IsValidationError(validationErr))
	assert.True(t, IsStorageError(storageErr))

	assert.False(t, IsParseError(validationErr))
	assert.False(t, IsValidationError(storageErr))
	assert.False(t, IsStorageError(parseErr))
}

// Benchmark tests
func BenchmarkValidator_ValidateMeasurement(b *testing.B) {
	logger := &MockLogger{}
	logger.On("Debug", mock.Anything, mock.Anything).Maybe()

	validator := NewValidator(logger)
	measurement := &Measurement{
		Key:       "pcr-0",
		Algorithm: AlgorithmSHA256,
		Digest:    make([]byte, SHA256Length),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateMeasurement(measurement)
	}
}
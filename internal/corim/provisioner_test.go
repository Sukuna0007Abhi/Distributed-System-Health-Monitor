package corim

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock Store for testing
type MockStore struct {
	mock.Mock
}

func (m *MockStore) StoreProfile(ctx context.Context, profile *Profile) error {
	args := m.Called(ctx, profile)
	return args.Error(0)
}

func (m *MockStore) GetProfile(ctx context.Context, profileID string) (*Profile, error) {
	args := m.Called(ctx, profileID)
	return args.Get(0).(*Profile), args.Error(1)
}

func (m *MockStore) StoreReferenceValue(ctx context.Context, refValue *ReferenceValue) error {
	args := m.Called(ctx, refValue)
	return args.Error(0)
}

func (m *MockStore) GetReferenceValue(ctx context.Context, key string) (*ReferenceValue, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*ReferenceValue), args.Error(1)
}

func (m *MockStore) GetReferenceValuesByEnvironment(ctx context.Context, envID *EnvironmentIdentifier) ([]*ReferenceValue, error) {
	args := m.Called(ctx, envID)
	return args.Get(0).([]*ReferenceValue), args.Error(1)
}

func (m *MockStore) ListProfiles(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStore) GetProfileSummaries(ctx context.Context) ([]*ProfileSummary, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*ProfileSummary), args.Error(1)
}

func (m *MockStore) DeleteProfile(ctx context.Context, profileID string) error {
	args := m.Called(ctx, profileID)
	return args.Error(0)
}

func (m *MockStore) Exists(ctx context.Context, profileID string) (bool, error) {
	args := m.Called(ctx, profileID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStore) GetStats(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockStore) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Mock Parser for testing
type MockParser struct {
	mock.Mock
}

func (m *MockParser) ParseFile(ctx context.Context, path string) (*ParseResult, error) {
	args := m.Called(ctx, path)
	return args.Get(0).(*ParseResult), args.Error(1)
}

func (m *MockParser) Parse(ctx context.Context, data []byte) (*ParseResult, error) {
	args := m.Called(ctx, data)
	return args.Get(0).(*ParseResult), args.Error(1)
}

func (m *MockParser) Validate(profile *Profile) (*ValidationResult, error) {
	args := m.Called(profile)
	return args.Get(0).(*ValidationResult), args.Error(1)
}

func createTestProvisioningResult() *ProvisioningResult {
	return &ProvisioningResult{
		ProfileID:       "test-profile-001",
		RefValuesStored: 2,
		KeysCreated:     []string{"test-key-1", "test-key-2"},
		Duration:        100 * time.Millisecond,
		Warnings:        []string{},
	}
}

func TestProvisioner_ProvisionProfile(t *testing.T) {
	tests := []struct {
		name        string
		profile     *Profile
		storeExists bool
		expectError bool
	}{
		{
			name:        "nil profile",
			profile:     nil,
			expectError: true,
		},
		{
			name:        "duplicate profile",
			profile:     createTestProfile(),
			storeExists: true,
			expectError: true,
		},
		{
			name:        "valid new profile",
			profile:     createTestProfile(),
			storeExists: false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockParser := &MockParser{}
			logger := &MockLogger{}
			
			// Set up mock expectations
			if tt.profile != nil {
				mockStore.On("Exists", mock.Anything, tt.profile.ID).Return(tt.storeExists, nil)
				
				if !tt.storeExists {
					mockStore.On("StoreProfile", mock.Anything, tt.profile).Return(nil)
					for _, refValue := range tt.profile.RefValues {
						mockStore.On("StoreReferenceValue", mock.Anything, refValue).Return(nil)
					}
				}
			}

			logger.On("Info", mock.Anything, mock.Anything).Maybe()
			logger.On("Warn", mock.Anything, mock.Anything).Maybe()

			provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

			ctx := context.Background()
			result, err := provisioner.ProvisionProfile(ctx, tt.profile)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.profile.ID, result.ProfileID)
			}

			mockStore.AssertExpectations(t)
		})
	}
}

func TestProvisioner_GetReferenceValues(t *testing.T) {
	tests := []struct {
		name          string
		environmentID *EnvironmentIdentifier
		returnValues  []*ReferenceValue
		expectError   bool
	}{
		{
			name:          "nil environment",
			environmentID: nil,
			expectError:   true,
		},
		{
			name: "valid environment",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			returnValues: []*ReferenceValue{
				{
					Key: "test-key-1",
					Environment: &EnvironmentIdentifier{
						Class:    EnvClassTPM,
						Instance: "test-instance",
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockParser := &MockParser{}
			logger := &MockLogger{}

			// Set up mock expectations
			if tt.environmentID != nil {
				mockStore.On("GetReferenceValuesByEnvironment", mock.Anything, tt.environmentID).
					Return(tt.returnValues, nil)
			}

			logger.On("Debug", mock.Anything, mock.Anything).Maybe()

			provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

			ctx := context.Background()
			result, err := provisioner.GetReferenceValues(ctx, tt.environmentID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, len(tt.returnValues), result.Count)
				assert.Equal(t, tt.returnValues, result.Values)
			}

			if tt.environmentID != nil {
				mockStore.AssertExpectations(t)
			}
		})
	}
}

func TestProvisioner_DeleteProfile(t *testing.T) {
	tests := []struct {
		name        string
		profileID   string
		expectError bool
	}{
		{
			name:        "empty profile ID",
			profileID:   "",
			expectError: true,
		},
		{
			name:        "valid profile ID",
			profileID:   "test-profile-001",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockParser := &MockParser{}
			logger := &MockLogger{}

			// Set up mock expectations
			if tt.profileID != "" {
				mockStore.On("DeleteProfile", mock.Anything, tt.profileID).Return(nil)
			}

			logger.On("Info", mock.Anything, mock.Anything).Maybe()

			provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

			ctx := context.Background()
			err := provisioner.DeleteProfile(ctx, tt.profileID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.profileID != "" {
				mockStore.AssertExpectations(t)
			}
		})
	}
}

func TestProvisioner_ListProfiles(t *testing.T) {
	mockStore := &MockStore{}
	mockParser := &MockParser{}
	logger := &MockLogger{}

	expectedSummaries := []*ProfileSummary{
		{
			ID:       "profile-1",
			Name:     "Profile 1",
			LoadTime: time.Now(),
			RefCount: 5,
		},
		{
			ID:       "profile-2",
			Name:     "Profile 2",
			LoadTime: time.Now(),
			RefCount: 3,
		},
	}

	mockStore.On("GetProfileSummaries", mock.Anything).Return(expectedSummaries, nil)

	provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

	ctx := context.Background()
	summaries, err := provisioner.ListProfiles(ctx)

	assert.NoError(t, err)
	assert.Equal(t, expectedSummaries, summaries)
	mockStore.AssertExpectations(t)
}

func TestProvisioner_ValidateEnvironment(t *testing.T) {
	tests := []struct {
		name          string
		environmentID *EnvironmentIdentifier
		expectError   bool
	}{
		{
			name:          "nil environment",
			environmentID: nil,
			expectError:   true,
		},
		{
			name: "empty class",
			environmentID: &EnvironmentIdentifier{
				Class: "",
			},
			expectError: true,
		},
		{
			name: "invalid class",
			environmentID: &EnvironmentIdentifier{
				Class: "invalid-class",
			},
			expectError: true,
		},
		{
			name: "valid TPM environment",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			expectError: false,
		},
		{
			name: "valid TEE environment",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTEE,
				Instance: "test-instance",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockParser := &MockParser{}
			logger := &MockLogger{}

			provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

			err := provisioner.ValidateEnvironment(tt.environmentID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvisioner_QueryMeasurementsForPCR(t *testing.T) {
	testRefValues := []*ReferenceValue{
		{
			Key: "test-key-1",
			Environment: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			Measurements: []*Measurement{
				{
					Key:       "pcr-0",
					Algorithm: AlgorithmSHA256,
					Digest:    make([]byte, SHA256Length),
				},
				{
					Key:       "pcr-1",
					Algorithm: AlgorithmSHA256,
					Digest:    make([]byte, SHA256Length),
				},
			},
		},
	}

	tests := []struct {
		name            string
		pcrIndex        string
		environmentID   *EnvironmentIdentifier
		expectedCount   int
		expectError     bool
	}{
		{
			name:          "nil environment",
			pcrIndex:      "0",
			environmentID: nil,
			expectError:   true,
		},
		{
			name:      "PCR 0 query",
			pcrIndex:  "0",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:      "PCR 1 query",
			pcrIndex:  "1",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:      "Non-existent PCR",
			pcrIndex:  "99",
			environmentID: &EnvironmentIdentifier{
				Class:    EnvClassTPM,
				Instance: "test-instance",
			},
			expectedCount: 0,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &MockStore{}
			mockParser := &MockParser{}
			logger := &MockLogger{}

			// Set up mock expectations
			if tt.environmentID != nil {
				mockStore.On("GetReferenceValuesByEnvironment", mock.Anything, tt.environmentID).
					Return(testRefValues, nil)
			}

			logger.On("Debug", mock.Anything, mock.Anything).Maybe()

			provisioner := NewProvisioner(mockStore, mockParser, nil, logger)

			ctx := context.Background()
			measurements, err := provisioner.QueryMeasurementsForPCR(ctx, tt.pcrIndex, tt.environmentID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, measurements, tt.expectedCount)
			}

			if tt.environmentID != nil {
				mockStore.AssertExpectations(t)
			}
		})
	}
}

// Benchmark tests
func BenchmarkProvisioner_GetReferenceValues(b *testing.B) {
	mockStore := &MockStore{}
	mockParser := &MockParser{}
	logger := &MockLogger{}

	envID := &EnvironmentIdentifier{
		Class:    EnvClassTPM,
		Instance: "test-instance",
	}

	testRefValues := make([]*ReferenceValue, 100)
	for i := 0; i < 100; i++ {
		testRefValues[i] = &ReferenceValue{
			Key:         fmt.Sprintf("test-key-%d", i),
			Environment: envID,
		}
	}

	mockStore.On("GetReferenceValuesByEnvironment", mock.Anything, envID).
		Return(testRefValues, nil)
	logger.On("Debug", mock.Anything, mock.Anything).Maybe()

	provisioner := NewProvisioner(mockStore, mockParser, nil, logger)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provisioner.GetReferenceValues(ctx, envID)
	}
}
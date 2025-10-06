package corim

import (
	"context"
	"fmt"
	"time"
)

// Provisioner handles the extraction and storage of reference values from CoRIM profiles
type Provisioner struct {
	store   StoreInterface
	parser  ParserInterface
	metrics *Metrics
	logger  Logger
}

// NewProvisioner creates a new CoRIM provisioner
func NewProvisioner(store StoreInterface, parser ParserInterface, metrics *Metrics, logger Logger) *Provisioner {
	return &Provisioner{
		store:   store,
		parser:  parser,
		metrics: metrics,
		logger:  logger,
	}
}

// ProvisionProfile provisions a CoRIM profile by storing it and extracting reference values
func (p *Provisioner) ProvisionProfile(ctx context.Context, profile *Profile) (*ProvisioningResult, error) {
	start := time.Now()
	
	if profile == nil {
		return nil, NewProvisioningError(ErrInvalidCoRIM, "", "validation", "profile cannot be nil")
	}

	p.logger.Info("Starting profile provisioning", 
		"profile_id", profile.ID,
		"ref_values_count", len(profile.RefValues))

	// Check if profile already exists
	exists, err := p.store.Exists(ctx, profile.ID)
	if err != nil {
		return nil, NewProvisioningError(err, profile.ID, "existence_check", "failed to check if profile exists")
	}

	if exists {
		return nil, NewProvisioningError(ErrDuplicateProfile, profile.ID, "validation", 
			fmt.Sprintf("profile %s already exists", profile.ID))
	}

	var warnings []string
	var keysCreated []string

	// Store the profile itself
	if err := p.store.StoreProfile(ctx, profile); err != nil {
		return nil, NewProvisioningError(err, profile.ID, "profile_storage", "failed to store profile")
	}

	// Store individual reference values
	refValuesStored := 0
	for key, refValue := range profile.RefValues {
		if err := p.store.StoreReferenceValue(ctx, refValue); err != nil {
			warning := fmt.Sprintf("Failed to store reference value %s: %v", key, err)
			warnings = append(warnings, warning)
			p.logger.Warn("Reference value storage failed", "key", key, "error", err)
			continue
		}
		keysCreated = append(keysCreated, key)
		refValuesStored++
	}

	duration := time.Since(start)

	// Update metrics
	if p.metrics != nil {
		p.metrics.IncProfilesLoaded()
		p.metrics.AddReferenceValuesStored(float64(refValuesStored))
	}

	result := &ProvisioningResult{
		ProfileID:       profile.ID,
		RefValuesStored: refValuesStored,
		KeysCreated:     keysCreated,
		Duration:        duration,
		Warnings:        warnings,
	}

	p.logger.Info("Profile provisioning completed", 
		"profile_id", profile.ID,
		"ref_values_stored", refValuesStored,
		"duration", duration,
		"warnings_count", len(warnings))

	return result, nil
}

// ProvisionFromFile provisions a CoRIM profile from a file
func (p *Provisioner) ProvisionFromFile(ctx context.Context, filePath string) (*ProvisioningResult, error) {
	// Parse the file
	parseResult, err := p.parser.ParseFile(ctx, filePath)
	if err != nil {
		return nil, NewProvisioningError(err, "", "parsing", fmt.Sprintf("failed to parse file %s", filePath))
	}

	// Provision the parsed profile
	result, err := p.ProvisionProfile(ctx, parseResult.Profile)
	if err != nil {
		return nil, err
	}

	// Add parsing warnings to provisioning result
	result.Warnings = append(result.Warnings, parseResult.Warnings...)

	return result, nil
}

// GetReferenceValues retrieves reference values for a specific environment
func (p *Provisioner) GetReferenceValues(ctx context.Context, environmentID *EnvironmentIdentifier) (*QueryResult, error) {
	start := time.Now()

	if environmentID == nil {
		return nil, fmt.Errorf("%w: environment identifier cannot be nil", ErrInvalidEnvironment)
	}

	p.logger.Debug("Querying reference values", 
		"environment_class", environmentID.Class,
		"environment_instance", environmentID.Instance)

	values, err := p.store.GetReferenceValuesByEnvironment(ctx, environmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query reference values: %w", err)
	}

	queryTime := time.Since(start)

	// Update metrics
	if p.metrics != nil {
		p.metrics.ObserveQueryTime(queryTime.Seconds())
	}

	result := &QueryResult{
		Values:      values,
		Environment: environmentID,
		Count:       len(values),
		QueryTime:   queryTime,
	}

	p.logger.Debug("Reference values query completed", 
		"environment_class", environmentID.Class,
		"values_found", len(values),
		"query_time", queryTime)

	return result, nil
}

// GetReferenceValue retrieves a specific reference value by key
func (p *Provisioner) GetReferenceValue(ctx context.Context, key string) (*ReferenceValue, error) {
	if key == "" {
		return nil, fmt.Errorf("%w: key cannot be empty", ErrInvalidCoRIM)
	}

	return p.store.GetReferenceValue(ctx, key)
}

// ListProfiles returns a list of all loaded profiles
func (p *Provisioner) ListProfiles(ctx context.Context) ([]*ProfileSummary, error) {
	return p.store.GetProfileSummaries(ctx)
}

// GetProfile retrieves a specific profile by ID
func (p *Provisioner) GetProfile(ctx context.Context, profileID string) (*Profile, error) {
	if profileID == "" {
		return nil, fmt.Errorf("%w: profile ID cannot be empty", ErrProfileNotFound)
	}

	return p.store.GetProfile(ctx, profileID)
}

// DeleteProfile removes a profile and all its reference values
func (p *Provisioner) DeleteProfile(ctx context.Context, profileID string) error {
	if profileID == "" {
		return fmt.Errorf("%w: profile ID cannot be empty", ErrProfileNotFound)
	}

	p.logger.Info("Deleting profile", "profile_id", profileID)

	err := p.store.DeleteProfile(ctx, profileID)
	if err != nil {
		return fmt.Errorf("failed to delete profile %s: %w", profileID, err)
	}

	p.logger.Info("Profile deleted successfully", "profile_id", profileID)
	return nil
}

// UpdateProfile updates an existing profile (replaces it)
func (p *Provisioner) UpdateProfile(ctx context.Context, profile *Profile) (*ProvisioningResult, error) {
	if profile == nil {
		return nil, NewProvisioningError(ErrInvalidCoRIM, "", "validation", "profile cannot be nil")
	}

	// Check if profile exists
	exists, err := p.store.Exists(ctx, profile.ID)
	if err != nil {
		return nil, NewProvisioningError(err, profile.ID, "existence_check", "failed to check if profile exists")
	}

	if !exists {
		return nil, NewProvisioningError(ErrProfileNotFound, profile.ID, "validation", 
			fmt.Sprintf("profile %s does not exist", profile.ID))
	}

	// Delete existing profile first
	if err := p.store.DeleteProfile(ctx, profile.ID); err != nil {
		return nil, NewProvisioningError(err, profile.ID, "cleanup", "failed to delete existing profile")
	}

	// Provision the updated profile
	return p.ProvisionProfile(ctx, profile)
}

// QueryMeasurementsForPCR queries reference values for a specific PCR
func (p *Provisioner) QueryMeasurementsForPCR(ctx context.Context, pcrIndex string, environmentID *EnvironmentIdentifier) ([]*Measurement, error) {
	if environmentID == nil {
		return nil, fmt.Errorf("%w: environment identifier cannot be nil", ErrInvalidEnvironment)
	}

	// Get all reference values for the environment
	queryResult, err := p.GetReferenceValues(ctx, environmentID)
	if err != nil {
		return nil, err
	}

	var measurements []*Measurement

	// Filter measurements for the specific PCR
	for _, refValue := range queryResult.Values {
		for _, measurement := range refValue.Measurements {
			if measurement.Key == pcrIndex || measurement.Key == fmt.Sprintf("pcr-%s", pcrIndex) {
				measurements = append(measurements, measurement)
			}
		}
	}

	p.logger.Debug("PCR measurements query completed",
		"pcr_index", pcrIndex,
		"environment_class", environmentID.Class,
		"measurements_found", len(measurements))

	return measurements, nil
}

// ValidateEnvironment validates that an environment identifier is properly formed
func (p *Provisioner) ValidateEnvironment(environmentID *EnvironmentIdentifier) error {
	if environmentID == nil {
		return fmt.Errorf("%w: environment identifier cannot be nil", ErrInvalidEnvironment)
	}

	if environmentID.Class == "" {
		return fmt.Errorf("%w: environment class is required", ErrInvalidEnvironment)
	}

	// Validate known environment classes
	switch environmentID.Class {
	case EnvClassTPM, EnvClassTEE, EnvClassUEFI, EnvClassGeneric:
		// Valid classes
	default:
		return fmt.Errorf("%w: unsupported environment class %s", ErrInvalidEnvironment, environmentID.Class)
	}

	return nil
}

// GetProfileStats returns statistics for a specific profile
func (p *Provisioner) GetProfileStats(ctx context.Context, profileID string) (map[string]interface{}, error) {
	profile, err := p.store.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	stats := make(map[string]interface{})
	stats["profile_id"] = profile.ID
	stats["load_time"] = profile.LoadTime
	stats["reference_values_count"] = len(profile.RefValues)

	if profile.CoRIM != nil {
		stats["tags_count"] = len(profile.CoRIM.Tags)
	}

	// Count measurements by algorithm
	algorithmCounts := make(map[string]int)
	totalMeasurements := 0

	for _, refValue := range profile.RefValues {
		for _, measurement := range refValue.Measurements {
			algorithmCounts[measurement.Algorithm]++
			totalMeasurements++
		}
	}

	stats["total_measurements"] = totalMeasurements
	stats["measurements_by_algorithm"] = algorithmCounts

	// Count environments
	environmentClasses := make(map[string]int)
	for _, refValue := range profile.RefValues {
		if refValue.Environment != nil {
			environmentClasses[refValue.Environment.Class]++
		}
	}
	stats["environments_by_class"] = environmentClasses

	return stats, nil
}

// GetGlobalStats returns global statistics across all profiles
func (p *Provisioner) GetGlobalStats(ctx context.Context) (map[string]interface{}, error) {
	return p.store.GetStats(ctx)
}

// RefreshProfile re-parses and re-provisions a profile from its original file
func (p *Provisioner) RefreshProfile(ctx context.Context, profileID string) (*ProvisioningResult, error) {
	// Get the existing profile to find the file path
	profile, err := p.store.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	if profile.Metadata == nil || profile.Metadata.FilePath == "" {
		return nil, NewProvisioningError(ErrFileNotFound, profileID, "refresh", 
			"profile has no associated file path for refresh")
	}

	p.logger.Info("Refreshing profile from file", 
		"profile_id", profileID,
		"file_path", profile.Metadata.FilePath)

	// Delete the existing profile
	if err := p.store.DeleteProfile(ctx, profileID); err != nil {
		return nil, NewProvisioningError(err, profileID, "cleanup", "failed to delete existing profile during refresh")
	}

	// Re-provision from file
	return p.ProvisionFromFile(ctx, profile.Metadata.FilePath)
}

// BulkProvision provisions multiple profiles from a directory
func (p *Provisioner) BulkProvision(ctx context.Context, profilePaths []string) ([]*ProvisioningResult, []error) {
	var results []*ProvisioningResult
	var errors []error

	for _, path := range profilePaths {
		result, err := p.ProvisionFromFile(ctx, path)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to provision %s: %w", path, err))
			continue
		}
		results = append(results, result)
	}

	p.logger.Info("Bulk provisioning completed",
		"total_files", len(profilePaths),
		"successful", len(results),
		"failed", len(errors))

	return results, errors
}
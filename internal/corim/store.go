package corim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store provides Redis-based storage for CoRIM profiles and reference values
type Store struct {
	client redis.Cmdable
	config *StoreConfig
	logger Logger
}

// NewRedisStore creates a new Redis-backed CoRIM store
func NewRedisStore(config *StoreConfig, logger Logger) (*Store, error) {
	if config == nil {
		return nil, NewConfigurationError(ErrConfigurationInvalid, "config", nil, "store configuration is required")
	}

	// Create Redis client options
	opts := &redis.Options{
		Addr:         config.RedisAddr,
		Password:     config.RedisPassword,
		DB:           config.RedisDB,
		MaxRetries:   3,
		DialTimeout:  config.ConnectTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	// Handle connection pooling
	if config.MaxConnections > 0 {
		opts.PoolSize = config.MaxConnections
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, NewStorageError(err, "connection_test", "", MsgRedisConnectionFailed)
	}

	store := &Store{
		client: client,
		config: config,
		logger: logger,
	}

	logger.Info("CoRIM Redis store initialized", 
		"addr", config.RedisAddr, 
		"db", config.RedisDB,
		"key_prefix", config.KeyPrefix)

	return store, nil
}

// NewRedisStoreWithClient creates a store with an existing Redis client
func NewRedisStoreWithClient(client redis.Cmdable, config *StoreConfig, logger Logger) *Store {
	if config == nil {
		config = &StoreConfig{
			KeyPrefix: "corim",
			TTL:       24 * time.Hour,
		}
	}

	return &Store{
		client: client,
		config: config,
		logger: logger,
	}
}

// StoreProfile stores a complete CoRIM profile
func (s *Store) StoreProfile(ctx context.Context, profile *Profile) error {
	if profile == nil {
		return NewStorageError(ErrInvalidCoRIM, "store_profile", "", "profile cannot be nil")
	}

	key := s.getProfileKey(profile.ID)
	
	// Serialize profile to JSON
	data, err := json.Marshal(profile)
	if err != nil {
		return NewStorageError(err, "store_profile", key, "failed to serialize profile")
	}

	// Store with TTL
	err = s.client.Set(ctx, key, data, s.config.TTL).Err()
	if err != nil {
		return NewStorageError(err, "store_profile", key, "failed to store profile")
	}

	// Add to index
	if err := s.addToIndex(ctx, profile.ID); err != nil {
		s.logger.Warn("Failed to add profile to index", "profile_id", profile.ID, "error", err)
	}

	s.logger.Info("Profile stored successfully", 
		"profile_id", profile.ID,
		"key", key,
		"ttl", s.config.TTL)

	return nil
}

// GetProfile retrieves a CoRIM profile by ID
func (s *Store) GetProfile(ctx context.Context, profileID string) (*Profile, error) {
	if profileID == "" {
		return nil, NewStorageError(ErrProfileNotFound, "get_profile", "", "profile ID cannot be empty")
	}

	key := s.getProfileKey(profileID)
	
	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("%w: %s", ErrProfileNotFound, profileID)
		}
		return nil, NewStorageError(err, "get_profile", key, "failed to retrieve profile")
	}

	var profile Profile
	if err := json.Unmarshal([]byte(data), &profile); err != nil {
		return nil, NewStorageError(err, "get_profile", key, "failed to deserialize profile")
	}

	return &profile, nil
}

// StoreReferenceValue stores a single reference value
func (s *Store) StoreReferenceValue(ctx context.Context, refValue *ReferenceValue) error {
	if refValue == nil {
		return NewStorageError(ErrInvalidCoRIM, "store_reference_value", "", "reference value cannot be nil")
	}

	key := s.getReferenceValueKey(refValue.Key)
	
	// Serialize reference value to JSON
	data, err := json.Marshal(refValue)
	if err != nil {
		return NewStorageError(err, "store_reference_value", key, "failed to serialize reference value")
	}

	// Store with TTL
	err = s.client.Set(ctx, key, data, s.config.TTL).Err()
	if err != nil {
		return NewStorageError(err, "store_reference_value", key, "failed to store reference value")
	}

	s.logger.Debug("Reference value stored", 
		"key", refValue.Key,
		"redis_key", key,
		"environment", refValue.Environment.Class)

	return nil
}

// GetReferenceValue retrieves a single reference value by key
func (s *Store) GetReferenceValue(ctx context.Context, key string) (*ReferenceValue, error) {
	if key == "" {
		return nil, NewStorageError(ErrProfileNotFound, "get_reference_value", "", "key cannot be empty")
	}

	redisKey := s.getReferenceValueKey(key)
	
	data, err := s.client.Get(ctx, redisKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("%w: reference value with key %s", ErrProfileNotFound, key)
		}
		return nil, NewStorageError(err, "get_reference_value", redisKey, "failed to retrieve reference value")
	}

	var refValue ReferenceValue
	if err := json.Unmarshal([]byte(data), &refValue); err != nil {
		return nil, NewStorageError(err, "get_reference_value", redisKey, "failed to deserialize reference value")
	}

	return &refValue, nil
}

// GetReferenceValuesByEnvironment retrieves all reference values for a specific environment
func (s *Store) GetReferenceValuesByEnvironment(ctx context.Context, envID *EnvironmentIdentifier) ([]*ReferenceValue, error) {
	if envID == nil {
		return nil, NewStorageError(ErrInvalidEnvironment, "get_by_environment", "", "environment identifier cannot be nil")
	}

	// Create search pattern for the environment
	pattern := s.getReferenceValueSearchPattern(envID)
	
	// Find all keys matching the pattern
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, NewStorageError(err, "get_by_environment", pattern, "failed to search keys")
	}

	if len(keys) == 0 {
		return []*ReferenceValue{}, nil
	}

	// Retrieve all values
	var refValues []*ReferenceValue
	for _, key := range keys {
		data, err := s.client.Get(ctx, key).Result()
		if err != nil {
			s.logger.Warn("Failed to retrieve reference value", "key", key, "error", err)
			continue
		}

		var refValue ReferenceValue
		if err := json.Unmarshal([]byte(data), &refValue); err != nil {
			s.logger.Warn("Failed to deserialize reference value", "key", key, "error", err)
			continue
		}

		refValues = append(refValues, &refValue)
	}

	s.logger.Debug("Retrieved reference values by environment", 
		"environment", envID.Class,
		"count", len(refValues))

	return refValues, nil
}

// ListProfiles retrieves all profile IDs
func (s *Store) ListProfiles(ctx context.Context) ([]string, error) {
	indexKey := s.getIndexKey()
	
	members, err := s.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, NewStorageError(err, "list_profiles", indexKey, "failed to retrieve profile index")
	}

	return members, nil
}

// GetProfileSummaries retrieves lightweight summaries of all profiles
func (s *Store) GetProfileSummaries(ctx context.Context) ([]*ProfileSummary, error) {
	profileIDs, err := s.ListProfiles(ctx)
	if err != nil {
		return nil, err
	}

	var summaries []*ProfileSummary
	for _, profileID := range profileIDs {
		profile, err := s.GetProfile(ctx, profileID)
		if err != nil {
			s.logger.Warn("Failed to retrieve profile for summary", "profile_id", profileID, "error", err)
			continue
		}

		summary := &ProfileSummary{
			ID:          profile.ID,
			Name:        profile.Name,
			LoadTime:    profile.LoadTime,
			RefCount:    len(profile.RefValues),
			Metadata:    profile.Metadata,
		}

		if profile.Metadata != nil {
			summary.Version = profile.Metadata.Version
			summary.Description = profile.Metadata.Description
		}

		if profile.CoRIM != nil {
			summary.TagCount = len(profile.CoRIM.Tags)
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// DeleteProfile removes a profile and all its associated reference values
func (s *Store) DeleteProfile(ctx context.Context, profileID string) error {
	if profileID == "" {
		return NewStorageError(ErrProfileNotFound, "delete_profile", "", "profile ID cannot be empty")
	}

	// First, get the profile to find associated reference values
	profile, err := s.GetProfile(ctx, profileID)
	if err != nil {
		if IsProfileNotFound(err) {
			return nil // Already deleted
		}
		return err
	}

	// Delete all reference values
	for key := range profile.RefValues {
		refKey := s.getReferenceValueKey(key)
		if err := s.client.Del(ctx, refKey).Err(); err != nil {
			s.logger.Warn("Failed to delete reference value", "key", refKey, "error", err)
		}
	}

	// Delete the profile itself
	profileKey := s.getProfileKey(profileID)
	if err := s.client.Del(ctx, profileKey).Err(); err != nil {
		return NewStorageError(err, "delete_profile", profileKey, "failed to delete profile")
	}

	// Remove from index
	if err := s.removeFromIndex(ctx, profileID); err != nil {
		s.logger.Warn("Failed to remove profile from index", "profile_id", profileID, "error", err)
	}

	s.logger.Info("Profile deleted successfully", 
		"profile_id", profileID,
		"reference_values_deleted", len(profile.RefValues))

	return nil
}

// Exists checks if a profile exists
func (s *Store) Exists(ctx context.Context, profileID string) (bool, error) {
	if profileID == "" {
		return false, nil
	}

	key := s.getProfileKey(profileID)
	count, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, NewStorageError(err, "exists", key, "failed to check existence")
	}

	return count > 0, nil
}

// GetStats returns statistics about stored data
func (s *Store) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count profiles
	profileIDs, err := s.ListProfiles(ctx)
	if err != nil {
		return nil, err
	}
	stats["profiles_count"] = len(profileIDs)

	// Count reference values
	refValuePattern := s.getReferenceValueKey("*")
	refValueKeys, err := s.client.Keys(ctx, refValuePattern).Result()
	if err != nil {
		s.logger.Warn("Failed to count reference values", "error", err)
		stats["reference_values_count"] = 0
	} else {
		stats["reference_values_count"] = len(refValueKeys)
	}

	// Get memory usage info if supported
	if info, err := s.client.Info(ctx, "memory").Result(); err == nil {
		// Parse memory info from Redis INFO command
		lines := strings.Split(info, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "used_memory_human:") {
				stats["redis_memory_used"] = strings.TrimPrefix(line, "used_memory_human:")
				break
			}
		}
	}

	return stats, nil
}

// Close closes the Redis connection
func (s *Store) Close() error {
	if client, ok := s.client.(*redis.Client); ok {
		return client.Close()
	}
	return nil
}

// Helper methods for key generation

func (s *Store) getProfileKey(profileID string) string {
	return fmt.Sprintf("%s:%s:%s", s.config.KeyPrefix, ProfileKeyPrefix, profileID)
}

func (s *Store) getReferenceValueKey(key string) string {
	return fmt.Sprintf("%s:%s:%s", s.config.KeyPrefix, RefValueKeyPrefix, key)
}

func (s *Store) getIndexKey() string {
	return fmt.Sprintf("%s:%s", s.config.KeyPrefix, IndexKey)
}

func (s *Store) getReferenceValueSearchPattern(envID *EnvironmentIdentifier) string {
	// Create a search pattern based on environment
	pattern := fmt.Sprintf("%s:%s:%s:*", s.config.KeyPrefix, RefValueKeyPrefix, envID.Class)
	if envID.Instance != "" {
		pattern = fmt.Sprintf("%s:%s:%s:%s:*", s.config.KeyPrefix, RefValueKeyPrefix, envID.Class, envID.Instance)
	}
	return pattern
}

// Index management

func (s *Store) addToIndex(ctx context.Context, profileID string) error {
	indexKey := s.getIndexKey()
	return s.client.SAdd(ctx, indexKey, profileID).Err()
}

func (s *Store) removeFromIndex(ctx context.Context, profileID string) error {
	indexKey := s.getIndexKey()
	return s.client.SRem(ctx, indexKey, profileID).Err()
}
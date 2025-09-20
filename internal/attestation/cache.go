package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// EvidenceCache interface for caching attestation evidence and results
type EvidenceCache interface {
	// Get retrieves data from cache
	Get(ctx context.Context, key string) ([]byte, bool)
	
	// Set stores data in cache with TTL
	Set(ctx context.Context, key string, data []byte, ttl time.Duration) error
	
	// Delete removes data from cache
	Delete(ctx context.Context, key string) error
	
	// Exists checks if key exists
	Exists(ctx context.Context, key string) bool
	
	// Clear clears all cache entries
	Clear(ctx context.Context) error
	
	// Size returns the number of entries in cache
	Size(ctx context.Context) int64
	
	// Close closes the cache
	Close() error
}

// RedisEvidenceCache implements EvidenceCache using Redis Cluster
type RedisEvidenceCache struct {
	client *redis.ClusterClient
	logger *logrus.Logger
	prefix string
}

// NewRedisEvidenceCache creates a new Redis-based evidence cache
func NewRedisEvidenceCache(ttl time.Duration) (*RedisEvidenceCache, error) {
	// Redis cluster configuration would come from config
	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: []string{
			"localhost:7000",
			"localhost:7001", 
			"localhost:7002",
			"localhost:7003",
			"localhost:7004",
			"localhost:7005",
		},
		MaxRetries:      3,
		MaxRetryBackoff: 500 * time.Millisecond,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolSize:        10,
		PoolTimeout:     30 * time.Second,
		IdleTimeout:     10 * time.Minute,
		IdleCheckFrequency: 1 * time.Minute,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis cluster: %w", err)
	}

	return &RedisEvidenceCache{
		client: client,
		logger: logrus.New(),
		prefix: "attestation:cache:",
	}, nil
}

// Get retrieves data from Redis cache
func (c *RedisEvidenceCache) Get(ctx context.Context, key string) ([]byte, bool) {
	fullKey := c.prefix + key
	
	result, err := c.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, false
		}
		c.logger.WithError(err).WithField("key", key).Error("Failed to get from cache")
		return nil, false
	}

	return []byte(result), true
}

// Set stores data in Redis cache with TTL
func (c *RedisEvidenceCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	fullKey := c.prefix + key
	
	if err := c.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		c.logger.WithError(err).WithField("key", key).Error("Failed to set cache")
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}

// Delete removes data from Redis cache
func (c *RedisEvidenceCache) Delete(ctx context.Context, key string) error {
	fullKey := c.prefix + key
	
	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		c.logger.WithError(err).WithField("key", key).Error("Failed to delete from cache")
		return fmt.Errorf("failed to delete from cache: %w", err)
	}

	return nil
}

// Exists checks if key exists in Redis cache
func (c *RedisEvidenceCache) Exists(ctx context.Context, key string) bool {
	fullKey := c.prefix + key
	
	result, err := c.client.Exists(ctx, fullKey).Result()
	if err != nil {
		c.logger.WithError(err).WithField("key", key).Error("Failed to check existence")
		return false
	}

	return result > 0
}

// Clear clears all cache entries with the prefix
func (c *RedisEvidenceCache) Clear(ctx context.Context) error {
	pattern := c.prefix + "*"
	
	iter := c.client.Scan(ctx, 0, pattern, 0).Iterator()
	var keys []string
	
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys: %w", err)
		}
	}

	return nil
}

// Size returns the number of entries in cache
func (c *RedisEvidenceCache) Size(ctx context.Context) int64 {
	pattern := c.prefix + "*"
	
	var count int64
	iter := c.client.Scan(ctx, 0, pattern, 0).Iterator()
	
	for iter.Next(ctx) {
		count++
	}
	
	return count
}

// Close closes the Redis connection
func (c *RedisEvidenceCache) Close() error {
	return c.client.Close()
}

// MemoryEvidenceCache implements EvidenceCache using in-memory storage
type MemoryEvidenceCache struct {
	data   map[string]*cacheEntry
	mutex  sync.RWMutex
	ttl    time.Duration
	logger *logrus.Logger
	stopCh chan struct{}
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryEvidenceCache creates a new in-memory evidence cache
func NewMemoryEvidenceCache(ttl time.Duration) *MemoryEvidenceCache {
	cache := &MemoryEvidenceCache{
		data:   make(map[string]*cacheEntry),
		ttl:    ttl,
		logger: logrus.New(),
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves data from memory cache
func (c *MemoryEvidenceCache) Get(ctx context.Context, key string) ([]byte, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// Entry expired, remove it
		delete(c.data, key)
		return nil, false
	}

	return entry.data, true
}

// Set stores data in memory cache with TTL
func (c *MemoryEvidenceCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ttl == 0 {
		ttl = c.ttl
	}

	c.data[key] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes data from memory cache
func (c *MemoryEvidenceCache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	return nil
}

// Exists checks if key exists in memory cache
func (c *MemoryEvidenceCache) Exists(ctx context.Context, key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return false
	}

	if time.Now().After(entry.expiresAt) {
		return false
	}

	return true
}

// Clear clears all cache entries
func (c *MemoryEvidenceCache) Clear(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data = make(map[string]*cacheEntry)
	return nil
}

// Size returns the number of entries in cache
func (c *MemoryEvidenceCache) Size(ctx context.Context) int64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return int64(len(c.data))
}

// Close closes the memory cache
func (c *MemoryEvidenceCache) Close() error {
	close(c.stopCh)
	return nil
}

// cleanup removes expired entries
func (c *MemoryEvidenceCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.removeExpired()
		case <-c.stopCh:
			return
		}
	}
}

// removeExpired removes expired cache entries
func (c *MemoryEvidenceCache) removeExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, entry := range c.data {
		if now.After(entry.expiresAt) {
			delete(c.data, key)
		}
	}
}

// TieredEvidenceCache implements a tiered caching strategy
type TieredEvidenceCache struct {
	l1Cache EvidenceCache // Fast in-memory cache
	l2Cache EvidenceCache // Persistent Redis cache
	logger  *logrus.Logger
}

// NewTieredEvidenceCache creates a new tiered evidence cache
func NewTieredEvidenceCache(l1TTL, l2TTL time.Duration) (*TieredEvidenceCache, error) {
	l1Cache := NewMemoryEvidenceCache(l1TTL)
	
	l2Cache, err := NewRedisEvidenceCache(l2TTL)
	if err != nil {
		// Fall back to memory cache if Redis is not available
		l2Cache = NewMemoryEvidenceCache(l2TTL)
	}

	return &TieredEvidenceCache{
		l1Cache: l1Cache,
		l2Cache: l2Cache,
		logger:  logrus.New(),
	}, nil
}

// Get retrieves data from tiered cache (L1 first, then L2)
func (c *TieredEvidenceCache) Get(ctx context.Context, key string) ([]byte, bool) {
	// Try L1 cache first
	if data, found := c.l1Cache.Get(ctx, key); found {
		return data, true
	}

	// Try L2 cache
	if data, found := c.l2Cache.Get(ctx, key); found {
		// Promote to L1 cache
		c.l1Cache.Set(ctx, key, data, 5*time.Minute)
		return data, true
	}

	return nil, false
}

// Set stores data in both cache tiers
func (c *TieredEvidenceCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	// Store in both caches
	if err := c.l1Cache.Set(ctx, key, data, ttl); err != nil {
		c.logger.WithError(err).Error("Failed to set L1 cache")
	}

	if err := c.l2Cache.Set(ctx, key, data, ttl); err != nil {
		c.logger.WithError(err).Error("Failed to set L2 cache")
		return err
	}

	return nil
}

// Delete removes data from both cache tiers
func (c *TieredEvidenceCache) Delete(ctx context.Context, key string) error {
	c.l1Cache.Delete(ctx, key)
	return c.l2Cache.Delete(ctx, key)
}

// Exists checks if key exists in either cache tier
func (c *TieredEvidenceCache) Exists(ctx context.Context, key string) bool {
	return c.l1Cache.Exists(ctx, key) || c.l2Cache.Exists(ctx, key)
}

// Clear clears both cache tiers
func (c *TieredEvidenceCache) Clear(ctx context.Context) error {
	c.l1Cache.Clear(ctx)
	return c.l2Cache.Clear(ctx)
}

// Size returns the size of L2 cache (persistent)
func (c *TieredEvidenceCache) Size(ctx context.Context) int64 {
	return c.l2Cache.Size(ctx)
}

// Close closes both cache tiers
func (c *TieredEvidenceCache) Close() error {
	c.l1Cache.Close()
	return c.l2Cache.Close()
}

// CacheStats provides cache statistics
type CacheStats struct {
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	HitRate     float64 `json:"hit_rate"`
	Size        int64   `json:"size"`
	Evictions   int64   `json:"evictions"`
	LastUpdated time.Time `json:"last_updated"`
}

// StatsCollector collects cache statistics
type StatsCollector struct {
	cache  EvidenceCache
	stats  *CacheStats
	mutex  sync.RWMutex
	logger *logrus.Logger
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector(cache EvidenceCache) *StatsCollector {
	return &StatsCollector{
		cache: cache,
		stats: &CacheStats{
			LastUpdated: time.Now(),
		},
		logger: logrus.New(),
	}
}

// RecordHit records a cache hit
func (s *StatsCollector) RecordHit() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.stats.Hits++
	s.updateHitRate()
}

// RecordMiss records a cache miss
func (s *StatsCollector) RecordMiss() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.stats.Misses++
	s.updateHitRate()
}

// RecordEviction records a cache eviction
func (s *StatsCollector) RecordEviction() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.stats.Evictions++
}

// updateHitRate calculates the hit rate
func (s *StatsCollector) updateHitRate() {
	total := s.stats.Hits + s.stats.Misses
	if total > 0 {
		s.stats.HitRate = float64(s.stats.Hits) / float64(total)
	}
	s.stats.LastUpdated = time.Now()
}

// GetStats returns current cache statistics
func (s *StatsCollector) GetStats(ctx context.Context) *CacheStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	stats := *s.stats
	stats.Size = s.cache.Size(ctx)
	
	return &stats
}

// Reset resets all statistics
func (s *StatsCollector) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.stats = &CacheStats{
		LastUpdated: time.Now(),
	}
}

// InstrumentedCache wraps a cache with statistics collection
type InstrumentedCache struct {
	cache     EvidenceCache
	collector *StatsCollector
}

// NewInstrumentedCache creates a new instrumented cache
func NewInstrumentedCache(cache EvidenceCache) *InstrumentedCache {
	return &InstrumentedCache{
		cache:     cache,
		collector: NewStatsCollector(cache),
	}
}

// Get retrieves data and records statistics
func (c *InstrumentedCache) Get(ctx context.Context, key string) ([]byte, bool) {
	data, found := c.cache.Get(ctx, key)
	
	if found {
		c.collector.RecordHit()
	} else {
		c.collector.RecordMiss()
	}
	
	return data, found
}

// Set stores data
func (c *InstrumentedCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	return c.cache.Set(ctx, key, data, ttl)
}

// Delete removes data
func (c *InstrumentedCache) Delete(ctx context.Context, key string) error {
	return c.cache.Delete(ctx, key)
}

// Exists checks if key exists
func (c *InstrumentedCache) Exists(ctx context.Context, key string) bool {
	return c.cache.Exists(ctx, key)
}

// Clear clears all cache entries
func (c *InstrumentedCache) Clear(ctx context.Context) error {
	return c.cache.Clear(ctx)
}

// Size returns the number of entries in cache
func (c *InstrumentedCache) Size(ctx context.Context) int64 {
	return c.cache.Size(ctx)
}

// Close closes the cache
func (c *InstrumentedCache) Close() error {
	return c.cache.Close()
}

// GetStats returns cache statistics
func (c *InstrumentedCache) GetStats(ctx context.Context) *CacheStats {
	return c.collector.GetStats(ctx)
}

// ResetStats resets cache statistics
func (c *InstrumentedCache) ResetStats() {
	c.collector.Reset()
}

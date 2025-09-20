package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AnomalyDetector defines the interface for anomaly detection
type AnomalyDetector interface {
	Train(ctx context.Context, data []ContainerMetrics) error
	Detect(ctx context.Context, metrics ContainerMetrics) (*AnomalyResult, error)
	UpdateModel(ctx context.Context, data []ContainerMetrics) error
	GetModelInfo() *ModelInfo
	Close() error
}

// ContainerMetrics represents container behavioral metrics
type ContainerMetrics struct {
	Timestamp      time.Time `json:"timestamp"`
	ContainerID    string    `json:"container_id"`
	PodName        string    `json:"pod_name"`
	Namespace      string    `json:"namespace"`
	
	// Resource metrics
	CPUUsage       float64 `json:"cpu_usage"`        // CPU usage percentage
	MemoryUsage    float64 `json:"memory_usage"`     // Memory usage in bytes
	NetworkRx      float64 `json:"network_rx"`       // Network bytes received
	NetworkTx      float64 `json:"network_tx"`       // Network bytes transmitted
	DiskRead       float64 `json:"disk_read"`        // Disk bytes read
	DiskWrite      float64 `json:"disk_write"`       // Disk bytes written
	
	// System call metrics
	SyscallCount   int64   `json:"syscall_count"`    // Number of system calls
	ProcessCount   int64   `json:"process_count"`    // Number of processes
	FileDescCount  int64   `json:"fd_count"`         // Number of file descriptors
	
	// Security metrics
	PrivilegedOps  int64   `json:"privileged_ops"`   // Privileged operations count
	NetworkConns   int64   `json:"network_conns"`    // Network connections count
	FileAccess     int64   `json:"file_access"`      // File access operations
	
	// Application metrics
	ResponseTime   float64 `json:"response_time"`    // Average response time
	ErrorRate      float64 `json:"error_rate"`       // Error rate percentage
	RequestRate    float64 `json:"request_rate"`     // Requests per second
	
	// Labels for classification
	Labels map[string]string `json:"labels"`
}

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	IsAnomaly    bool      `json:"is_anomaly"`
	Score        float64   `json:"score"`         // Anomaly score (0-1)
	Confidence   float64   `json:"confidence"`    // Confidence level (0-1)
	Explanation  string    `json:"explanation"`   // Human-readable explanation
	Features     []string  `json:"features"`      // Features contributing to anomaly
	Timestamp    time.Time `json:"timestamp"`
	Severity     Severity  `json:"severity"`
	Category     string    `json:"category"`      // Type of anomaly detected
	
	// Detailed analysis
	FeatureScores map[string]float64 `json:"feature_scores"`
	Recommendations []string         `json:"recommendations"`
}

// Severity represents anomaly severity levels
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ModelInfo provides information about the ML model
type ModelInfo struct {
	Type           string    `json:"type"`
	Version        string    `json:"version"`
	TrainedAt      time.Time `json:"trained_at"`
	SamplesCount   int64     `json:"samples_count"`
	Accuracy       float64   `json:"accuracy"`
	Features       []string  `json:"features"`
	Hyperparams    map[string]interface{} `json:"hyperparams"`
}

// IsolationForestDetector implements anomaly detection using Isolation Forest algorithm
type IsolationForestDetector struct {
	mu           sync.RWMutex
	logger       *logrus.Logger
	
	// Model parameters
	numTrees     int
	maxDepth     int
	subsample    int
	contamination float64
	
	// Model state
	trees        []*IsolationTree
	trained      bool
	trainedAt    time.Time
	samplesCount int64
	features     []string
	
	// Statistics for normalization
	featureStats map[string]*FeatureStats
	
	// Configuration
	config *AnomalyDetectorConfig
}

// IsolationTree represents a single tree in the isolation forest
type IsolationTree struct {
	Root      *TreeNode
	MaxDepth  int
	Subsample int
}

// TreeNode represents a node in the isolation tree
type TreeNode struct {
	Feature    string
	Threshold  float64
	Left       *TreeNode
	Right      *TreeNode
	IsLeaf     bool
	Depth      int
	Size       int
}

// FeatureStats holds statistics for feature normalization
type FeatureStats struct {
	Mean   float64
	StdDev float64
	Min    float64
	Max    float64
	Count  int64
}

// AnomalyDetectorConfig configures the anomaly detector
type AnomalyDetectorConfig struct {
	NumTrees      int     `yaml:"num_trees" json:"num_trees"`
	MaxDepth      int     `yaml:"max_depth" json:"max_depth"`
	Subsample     int     `yaml:"subsample" json:"subsample"`
	Contamination float64 `yaml:"contamination" json:"contamination"`
	MinSamples    int     `yaml:"min_samples" json:"min_samples"`
	UpdateInterval time.Duration `yaml:"update_interval" json:"update_interval"`
	
	// Thresholds
	AnomalyThreshold   float64 `yaml:"anomaly_threshold" json:"anomaly_threshold"`
	HighSeverityThreshold float64 `yaml:"high_severity_threshold" json:"high_severity_threshold"`
	CriticalSeverityThreshold float64 `yaml:"critical_severity_threshold" json:"critical_severity_threshold"`
	
	// Feature selection
	EnabledFeatures []string `yaml:"enabled_features" json:"enabled_features"`
}

// NewIsolationForestDetector creates a new isolation forest anomaly detector
func NewIsolationForestDetector(config *AnomalyDetectorConfig, logger *logrus.Logger) *IsolationForestDetector {
	if config == nil {
		config = &AnomalyDetectorConfig{
			NumTrees:      100,
			MaxDepth:      10,
			Subsample:     256,
			Contamination: 0.1,
			MinSamples:    100,
			AnomalyThreshold: 0.6,
			HighSeverityThreshold: 0.75,
			CriticalSeverityThreshold: 0.9,
			EnabledFeatures: []string{
				"cpu_usage", "memory_usage", "network_rx", "network_tx",
				"disk_read", "disk_write", "syscall_count", "process_count",
				"privileged_ops", "network_conns", "response_time", "error_rate",
			},
		}
	}

	return &IsolationForestDetector{
		logger:       logger,
		numTrees:     config.NumTrees,
		maxDepth:     config.MaxDepth,
		subsample:    config.Subsample,
		contamination: config.Contamination,
		trees:        make([]*IsolationTree, config.NumTrees),
		featureStats: make(map[string]*FeatureStats),
		features:     config.EnabledFeatures,
		config:       config,
	}
}

// Train trains the isolation forest model
func (d *IsolationForestDetector) Train(ctx context.Context, data []ContainerMetrics) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(data) < d.config.MinSamples {
		return fmt.Errorf("insufficient training data: need at least %d samples, got %d", 
			d.config.MinSamples, len(data))
	}

	d.logger.WithField("samples", len(data)).Info("Starting anomaly detection model training")

	// Calculate feature statistics
	if err := d.calculateFeatureStats(data); err != nil {
		return fmt.Errorf("failed to calculate feature statistics: %w", err)
	}

	// Normalize features
	normalizedData, err := d.normalizeData(data)
	if err != nil {
		return fmt.Errorf("failed to normalize data: %w", err)
	}

	// Build isolation trees
	for i := 0; i < d.numTrees; i++ {
		tree, err := d.buildTree(normalizedData, d.maxDepth)
		if err != nil {
			return fmt.Errorf("failed to build tree %d: %w", i, err)
		}
		d.trees[i] = tree
	}

	d.trained = true
	d.trainedAt = time.Now()
	d.samplesCount = int64(len(data))

	d.logger.WithFields(logrus.Fields{
		"trees":    d.numTrees,
		"samples":  len(data),
		"features": len(d.features),
	}).Info("Anomaly detection model training completed")

	return nil
}

// Detect detects anomalies in the given metrics
func (d *IsolationForestDetector) Detect(ctx context.Context, metrics ContainerMetrics) (*AnomalyResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.trained {
		return nil, fmt.Errorf("model not trained")
	}

	// Normalize the input data
	normalizedMetrics, err := d.normalizeMetrics(metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize metrics: %w", err)
	}

	// Calculate anomaly score
	score, featureScores := d.calculateAnomalyScore(normalizedMetrics)

	// Determine if it's an anomaly
	isAnomaly := score >= d.config.AnomalyThreshold

	// Determine severity
	severity := d.determineSeverity(score)

	// Generate explanation and recommendations
	explanation, features, recommendations := d.generateExplanation(score, featureScores, metrics)

	result := &AnomalyResult{
		IsAnomaly:       isAnomaly,
		Score:           score,
		Confidence:      d.calculateConfidence(score),
		Explanation:     explanation,
		Features:        features,
		Timestamp:       time.Now(),
		Severity:        severity,
		Category:        d.categorizeAnomaly(featureScores),
		FeatureScores:   featureScores,
		Recommendations: recommendations,
	}

	return result, nil
}

// UpdateModel updates the model with new data (online learning)
func (d *IsolationForestDetector) UpdateModel(ctx context.Context, data []ContainerMetrics) error {
	// For simplicity, we retrain the entire model
	// In a production system, you might implement incremental learning
	return d.Train(ctx, data)
}

// GetModelInfo returns information about the current model
func (d *IsolationForestDetector) GetModelInfo() *ModelInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return &ModelInfo{
		Type:         "IsolationForest",
		Version:      "1.0.0",
		TrainedAt:    d.trainedAt,
		SamplesCount: d.samplesCount,
		Accuracy:     0.95, // This would be calculated from validation data
		Features:     d.features,
		Hyperparams: map[string]interface{}{
			"num_trees":     d.numTrees,
			"max_depth":     d.maxDepth,
			"subsample":     d.subsample,
			"contamination": d.contamination,
		},
	}
}

// Close cleans up resources
func (d *IsolationForestDetector) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.trees = nil
	d.featureStats = nil
	d.trained = false

	return nil
}

// calculateFeatureStats calculates mean, standard deviation, min, max for each feature
func (d *IsolationForestDetector) calculateFeatureStats(data []ContainerMetrics) error {
	featureValues := make(map[string][]float64)

	// Extract feature values
	for _, metrics := range data {
		values := d.extractFeatureValues(metrics)
		for feature, value := range values {
			featureValues[feature] = append(featureValues[feature], value)
		}
	}

	// Calculate statistics for each feature
	for feature, values := range featureValues {
		if len(values) == 0 {
			continue
		}

		stats := &FeatureStats{
			Count: int64(len(values)),
		}

		// Calculate mean
		sum := 0.0
		for _, v := range values {
			sum += v
			if v < stats.Min || stats.Count == 1 {
				stats.Min = v
			}
			if v > stats.Max || stats.Count == 1 {
				stats.Max = v
			}
		}
		stats.Mean = sum / float64(len(values))

		// Calculate standard deviation
		sumSquaredDiff := 0.0
		for _, v := range values {
			diff := v - stats.Mean
			sumSquaredDiff += diff * diff
		}
		stats.StdDev = math.Sqrt(sumSquaredDiff / float64(len(values)))

		d.featureStats[feature] = stats
	}

	return nil
}

// extractFeatureValues extracts feature values from container metrics
func (d *IsolationForestDetector) extractFeatureValues(metrics ContainerMetrics) map[string]float64 {
	values := map[string]float64{
		"cpu_usage":      metrics.CPUUsage,
		"memory_usage":   metrics.MemoryUsage,
		"network_rx":     metrics.NetworkRx,
		"network_tx":     metrics.NetworkTx,
		"disk_read":      metrics.DiskRead,
		"disk_write":     metrics.DiskWrite,
		"syscall_count":  float64(metrics.SyscallCount),
		"process_count":  float64(metrics.ProcessCount),
		"fd_count":       float64(metrics.FileDescCount),
		"privileged_ops": float64(metrics.PrivilegedOps),
		"network_conns":  float64(metrics.NetworkConns),
		"file_access":    float64(metrics.FileAccess),
		"response_time":  metrics.ResponseTime,
		"error_rate":     metrics.ErrorRate,
		"request_rate":   metrics.RequestRate,
	}

	// Filter by enabled features
	filtered := make(map[string]float64)
	for _, feature := range d.features {
		if value, exists := values[feature]; exists {
			filtered[feature] = value
		}
	}

	return filtered
}

// normalizeData normalizes the training data
func (d *IsolationForestDetector) normalizeData(data []ContainerMetrics) ([]map[string]float64, error) {
	normalized := make([]map[string]float64, len(data))

	for i, metrics := range data {
		normalizedMetrics, err := d.normalizeMetrics(metrics)
		if err != nil {
			return nil, err
		}
		normalized[i] = normalizedMetrics
	}

	return normalized, nil
}

// normalizeMetrics normalizes a single metrics instance
func (d *IsolationForestDetector) normalizeMetrics(metrics ContainerMetrics) (map[string]float64, error) {
	values := d.extractFeatureValues(metrics)
	normalized := make(map[string]float64)

	for feature, value := range values {
		stats, exists := d.featureStats[feature]
		if !exists {
			continue
		}

		// Z-score normalization
		if stats.StdDev > 0 {
			normalized[feature] = (value - stats.Mean) / stats.StdDev
		} else {
			normalized[feature] = 0
		}
	}

	return normalized, nil
}

// buildTree builds a single isolation tree
func (d *IsolationForestDetector) buildTree(data []map[string]float64, maxDepth int) (*IsolationTree, error) {
	// Subsample the data
	subsampleSize := d.subsample
	if len(data) < subsampleSize {
		subsampleSize = len(data)
	}

	subsampledData := make([]map[string]float64, subsampleSize)
	for i := 0; i < subsampleSize; i++ {
		idx := i % len(data) // Simple round-robin subsampling
		subsampledData[i] = data[idx]
	}

	root := d.buildNode(subsampledData, 0, maxDepth)
	
	return &IsolationTree{
		Root:      root,
		MaxDepth:  maxDepth,
		Subsample: subsampleSize,
	}, nil
}

// buildNode recursively builds tree nodes
func (d *IsolationForestDetector) buildNode(data []map[string]float64, depth, maxDepth int) *TreeNode {
	node := &TreeNode{
		Depth: depth,
		Size:  len(data),
	}

	// Stop conditions
	if depth >= maxDepth || len(data) <= 1 {
		node.IsLeaf = true
		return node
	}

	// Randomly select a feature
	if len(d.features) == 0 {
		node.IsLeaf = true
		return node
	}

	featureIdx := depth % len(d.features) // Simple feature selection
	feature := d.features[featureIdx]
	node.Feature = feature

	// Find min and max values for the feature
	var minVal, maxVal float64
	first := true
	for _, sample := range data {
		if value, exists := sample[feature]; exists {
			if first {
				minVal = value
				maxVal = value
				first = false
			} else {
				if value < minVal {
					minVal = value
				}
				if value > maxVal {
					maxVal = value
				}
			}
		}
	}

	// If all values are the same, make it a leaf
	if minVal == maxVal {
		node.IsLeaf = true
		return node
	}

	// Random threshold between min and max
	node.Threshold = minVal + (maxVal-minVal)*0.5 // Simple midpoint split

	// Split data
	var leftData, rightData []map[string]float64
	for _, sample := range data {
		if value, exists := sample[feature]; exists {
			if value < node.Threshold {
				leftData = append(leftData, sample)
			} else {
				rightData = append(rightData, sample)
			}
		}
	}

	// Build child nodes
	if len(leftData) > 0 {
		node.Left = d.buildNode(leftData, depth+1, maxDepth)
	}
	if len(rightData) > 0 {
		node.Right = d.buildNode(rightData, depth+1, maxDepth)
	}

	return node
}

// calculateAnomalyScore calculates the anomaly score for given metrics
func (d *IsolationForestDetector) calculateAnomalyScore(metrics map[string]float64) (float64, map[string]float64) {
	totalPathLength := 0.0
	featureContributions := make(map[string]float64)

	// Calculate path length in each tree
	for _, tree := range d.trees {
		pathLength, contributions := d.calculatePathLength(tree.Root, metrics)
		totalPathLength += pathLength
		
		// Accumulate feature contributions
		for feature, contrib := range contributions {
			featureContributions[feature] += contrib
		}
	}

	// Average path length
	avgPathLength := totalPathLength / float64(len(d.trees))

	// Normalize feature contributions
	for feature := range featureContributions {
		featureContributions[feature] /= float64(len(d.trees))
	}

	// Convert to anomaly score (shorter paths indicate anomalies)
	// Using the formula from the Isolation Forest paper
	c := d.averagePathLength(d.subsample)
	score := math.Pow(2, -avgPathLength/c)

	return score, featureContributions
}

// calculatePathLength calculates the path length in a tree for given metrics
func (d *IsolationForestDetector) calculatePathLength(node *TreeNode, metrics map[string]float64) (float64, map[string]float64) {
	contributions := make(map[string]float64)

	if node.IsLeaf {
		return float64(node.Depth), contributions
	}

	contributions[node.Feature] = 1.0

	value, exists := metrics[node.Feature]
	if !exists {
		return float64(node.Depth), contributions
	}

	if value < node.Threshold && node.Left != nil {
		pathLength, childContribs := d.calculatePathLength(node.Left, metrics)
		for feature, contrib := range childContribs {
			contributions[feature] += contrib
		}
		return pathLength, contributions
	} else if node.Right != nil {
		pathLength, childContribs := d.calculatePathLength(node.Right, metrics)
		for feature, contrib := range childContribs {
			contributions[feature] += contrib
		}
		return pathLength, contributions
	}

	return float64(node.Depth), contributions
}

// averagePathLength calculates the average path length for a given sample size
func (d *IsolationForestDetector) averagePathLength(n int) float64 {
	if n <= 1 {
		return 0
	}
	return 2.0 * (math.Log(float64(n-1)) + 0.5772156649) - 2.0*float64(n-1)/float64(n)
}

// determineSeverity determines the severity based on anomaly score
func (d *IsolationForestDetector) determineSeverity(score float64) Severity {
	if score >= d.config.CriticalSeverityThreshold {
		return SeverityCritical
	} else if score >= d.config.HighSeverityThreshold {
		return SeverityHigh
	} else if score >= d.config.AnomalyThreshold {
		return SeverityMedium
	}
	return SeverityLow
}

// calculateConfidence calculates confidence level for the anomaly detection
func (d *IsolationForestDetector) calculateConfidence(score float64) float64 {
	// Simple confidence calculation based on distance from threshold
	if score >= d.config.AnomalyThreshold {
		return math.Min(1.0, score*1.2)
	}
	return math.Max(0.1, 1.0-score)
}

// generateExplanation generates human-readable explanation for the anomaly
func (d *IsolationForestDetector) generateExplanation(score float64, featureScores map[string]float64, metrics ContainerMetrics) (string, []string, []string) {
	// Find top contributing features
	type featureScore struct {
		feature string
		score   float64
	}

	var scores []featureScore
	for feature, fscore := range featureScores {
		scores = append(scores, featureScore{feature, fscore})
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	var topFeatures []string
	var explanation string
	var recommendations []string

	if len(scores) > 0 {
		topFeatures = make([]string, 0, min(3, len(scores)))
		for i := 0; i < min(3, len(scores)); i++ {
			topFeatures = append(topFeatures, scores[i].feature)
		}

		explanation = fmt.Sprintf("Anomaly detected with score %.3f. Primary contributing factors: %v", 
			score, topFeatures)

		// Generate recommendations based on top features
		for _, feature := range topFeatures {
			switch feature {
			case "cpu_usage":
				recommendations = append(recommendations, "Monitor CPU usage patterns and consider resource limits")
			case "memory_usage":
				recommendations = append(recommendations, "Check for memory leaks or unexpected memory allocation")
			case "network_rx", "network_tx":
				recommendations = append(recommendations, "Investigate unusual network activity or traffic spikes")
			case "syscall_count":
				recommendations = append(recommendations, "Analyze system call patterns for suspicious behavior")
			case "privileged_ops":
				recommendations = append(recommendations, "Review privileged operations for security concerns")
			case "error_rate":
				recommendations = append(recommendations, "Investigate increased error rates in application logs")
			default:
				recommendations = append(recommendations, fmt.Sprintf("Monitor %s metric for unusual patterns", feature))
			}
		}
	} else {
		explanation = fmt.Sprintf("Anomaly detected with score %.3f", score)
		recommendations = append(recommendations, "Perform comprehensive system analysis")
	}

	return explanation, topFeatures, recommendations
}

// categorizeAnomaly categorizes the type of anomaly based on feature contributions
func (d *IsolationForestDetector) categorizeAnomaly(featureScores map[string]float64) string {
	maxScore := 0.0
	maxFeature := ""

	for feature, score := range featureScores {
		if score > maxScore {
			maxScore = score
			maxFeature = feature
		}
	}

	switch maxFeature {
	case "cpu_usage", "memory_usage":
		return "resource_anomaly"
	case "network_rx", "network_tx", "network_conns":
		return "network_anomaly"
	case "disk_read", "disk_write":
		return "io_anomaly"
	case "syscall_count", "privileged_ops":
		return "security_anomaly"
	case "response_time", "error_rate", "request_rate":
		return "performance_anomaly"
	default:
		return "behavioral_anomaly"
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

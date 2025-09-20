package performance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// AutoscalingConfig configures autoscaling behavior
type AutoscalingConfig struct {
	ResourceID          string              `json:"resource_id"`
	ResourceType        ResourceType        `json:"resource_type"`
	MinReplicas         int                 `json:"min_replicas"`
	MaxReplicas         int                 `json:"max_replicas"`
	TargetCPU           float64             `json:"target_cpu"`
	TargetMemory        float64             `json:"target_memory"`
	TargetLatency       time.Duration       `json:"target_latency"`
	ScaleUpCooldown     time.Duration       `json:"scale_up_cooldown"`
	ScaleDownCooldown   time.Duration       `json:"scale_down_cooldown"`
	Policies            []ScalingPolicy     `json:"policies"`
	Triggers            []ScalingTrigger    `json:"triggers"`
	PredictiveScaling   bool                `json:"predictive_scaling"`
	Monitoring          MonitoringConfig    `json:"monitoring"`
}

// ResourceType represents the type of resource being scaled
type ResourceType int

const (
	ResourceTypePod ResourceType = iota
	ResourceTypeNode
	ResourceTypeService
	ResourceTypeDatabase
	ResourceTypeCache
	ResourceTypeLoadBalancer
)

func (r ResourceType) String() string {
	switch r {
	case ResourceTypePod:
		return "pod"
	case ResourceTypeNode:
		return "node"
	case ResourceTypeService:
		return "service"
	case ResourceTypeDatabase:
		return "database"
	case ResourceTypeCache:
		return "cache"
	case ResourceTypeLoadBalancer:
		return "load_balancer"
	default:
		return "unknown"
	}
}

// ScalingPolicy defines scaling behavior
type ScalingPolicy struct {
	Type            PolicyType        `json:"type"`
	Value           float64           `json:"value"`
	PeriodSeconds   int               `json:"period_seconds"`
	Pods            int               `json:"pods"`
	Percent         int               `json:"percent"`
	SelectPolicy    SelectPolicyType  `json:"select_policy"`
}

// PolicyType represents scaling policy types
type PolicyType int

const (
	PolicyTypePercent PolicyType = iota
	PolicyTypePods
	PolicyTypeFixedStep
	PolicyTypeExact
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypePercent:
		return "percent"
	case PolicyTypePods:
		return "pods"
	case PolicyTypeFixedStep:
		return "fixed_step"
	case PolicyTypeExact:
		return "exact"
	default:
		return "unknown"
	}
}

// SelectPolicyType represents how to select from multiple policies
type SelectPolicyType int

const (
	SelectPolicyMax SelectPolicyType = iota
	SelectPolicyMin
	SelectPolicyDisabled
)

func (s SelectPolicyType) String() string {
	switch s {
	case SelectPolicyMax:
		return "max"
	case SelectPolicyMin:
		return "min"
	case SelectPolicyDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// ScalingTrigger defines when scaling should occur
type ScalingTrigger struct {
	Type           TriggerType       `json:"type"`
	MetricName     string            `json:"metric_name"`
	Threshold      float64           `json:"threshold"`
	Comparison     ComparisonType    `json:"comparison"`
	Duration       time.Duration     `json:"duration"`
	Cooldown       time.Duration     `json:"cooldown"`
	Enabled        bool              `json:"enabled"`
}

// TriggerType represents trigger types
type TriggerType int

const (
	TriggerTypeCPU TriggerType = iota
	TriggerTypeMemory
	TriggerTypeLatency
	TriggerTypeThroughput
	TriggerTypeQueueLength
	TriggerTypeErrorRate
	TriggerTypeCustom
)

func (t TriggerType) String() string {
	switch t {
	case TriggerTypeCPU:
		return "cpu"
	case TriggerTypeMemory:
		return "memory"
	case TriggerTypeLatency:
		return "latency"
	case TriggerTypeThroughput:
		return "throughput"
	case TriggerTypeQueueLength:
		return "queue_length"
	case TriggerTypeErrorRate:
		return "error_rate"
	case TriggerTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// ComparisonType represents comparison operators
type ComparisonType int

const (
	ComparisonGreaterThan ComparisonType = iota
	ComparisonLessThan
	ComparisonGreaterOrEqual
	ComparisonLessOrEqual
	ComparisonEqual
	ComparisonNotEqual
)

func (c ComparisonType) String() string {
	switch c {
	case ComparisonGreaterThan:
		return "greater_than"
	case ComparisonLessThan:
		return "less_than"
	case ComparisonGreaterOrEqual:
		return "greater_or_equal"
	case ComparisonLessOrEqual:
		return "less_or_equal"
	case ComparisonEqual:
		return "equal"
	case ComparisonNotEqual:
		return "not_equal"
	default:
		return "unknown"
	}
}

// ScalingMetrics represents scaling metrics
type ScalingMetrics struct {
	ResourceID        string            `json:"resource_id"`
	Timestamp         time.Time         `json:"timestamp"`
	CurrentReplicas   int               `json:"current_replicas"`
	DesiredReplicas   int               `json:"desired_replicas"`
	CPUUtilization    float64           `json:"cpu_utilization"`
	MemoryUtilization float64           `json:"memory_utilization"`
	Latency           time.Duration     `json:"latency"`
	Throughput        float64           `json:"throughput"`
	QueueLength       int               `json:"queue_length"`
	ErrorRate         float64           `json:"error_rate"`
	ScalingEvents     []ScalingEvent    `json:"scaling_events"`
	Efficiency        ScalingEfficiency `json:"efficiency"`
}

// ScalingEvent represents a scaling event
type ScalingEvent struct {
	Timestamp     time.Time      `json:"timestamp"`
	Type          ScalingType    `json:"type"`
	FromReplicas  int            `json:"from_replicas"`
	ToReplicas    int            `json:"to_replicas"`
	Reason        string         `json:"reason"`
	TriggerMetric string         `json:"trigger_metric"`
	TriggerValue  float64        `json:"trigger_value"`
	Duration      time.Duration  `json:"duration"`
	Success       bool           `json:"success"`
	Error         string         `json:"error,omitempty"`
}

// ScalingType represents scaling direction
type ScalingType int

const (
	ScalingTypeUp ScalingType = iota
	ScalingTypeDown
	ScalingTypeNoChange
)

func (s ScalingType) String() string {
	switch s {
	case ScalingTypeUp:
		return "up"
	case ScalingTypeDown:
		return "down"
	case ScalingTypeNoChange:
		return "no_change"
	default:
		return "unknown"
	}
}

// ScalingEfficiency represents scaling efficiency metrics
type ScalingEfficiency struct {
	ResourceUtilization  float64       `json:"resource_utilization"`
	CostEfficiency       float64       `json:"cost_efficiency"`
	ResponseTime         time.Duration `json:"response_time"`
	Stability            float64       `json:"stability"`
	OverscalingRate      float64       `json:"overscaling_rate"`
	UnderscalingRate     float64       `json:"underscaling_rate"`
	Score                float64       `json:"score"`
}

// BatchConfig configures batch processing optimization
type BatchConfig struct {
	BatchID          string            `json:"batch_id"`
	MaxBatchSize     int               `json:"max_batch_size"`
	MinBatchSize     int               `json:"min_batch_size"`
	BatchTimeout     time.Duration     `json:"batch_timeout"`
	MaxWaitTime      time.Duration     `json:"max_wait_time"`
	ConcurrentBatches int              `json:"concurrent_batches"`
	RetryPolicy      RetryPolicy       `json:"retry_policy"`
	Compression      bool              `json:"compression"`
	Ordering         OrderingType      `json:"ordering"`
	Partitioning     PartitionConfig   `json:"partitioning"`
	Monitoring       MonitoringConfig  `json:"monitoring"`
}

// RetryPolicy defines retry behavior for batch processing
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	Jitter        bool          `json:"jitter"`
}

// OrderingType represents batch ordering requirements
type OrderingType int

const (
	OrderingNone OrderingType = iota
	OrderingFIFO
	OrderingLIFO
	OrderingPriority
	OrderingTimestamp
)

func (o OrderingType) String() string {
	switch o {
	case OrderingNone:
		return "none"
	case OrderingFIFO:
		return "fifo"
	case OrderingLIFO:
		return "lifo"
	case OrderingPriority:
		return "priority"
	case OrderingTimestamp:
		return "timestamp"
	default:
		return "unknown"
	}
}

// PartitionConfig configures batch partitioning
type PartitionConfig struct {
	Enabled       bool             `json:"enabled"`
	Strategy      PartitionStrategy `json:"strategy"`
	PartitionKey  string           `json:"partition_key"`
	PartitionCount int             `json:"partition_count"`
	LoadBalancing bool             `json:"load_balancing"`
}

// PartitionStrategy represents partitioning strategies
type PartitionStrategy int

const (
	PartitionStrategyHash PartitionStrategy = iota
	PartitionStrategyRange
	PartitionStrategyRoundRobin
	PartitionStrategyCustom
)

func (p PartitionStrategy) String() string {
	switch p {
	case PartitionStrategyHash:
		return "hash"
	case PartitionStrategyRange:
		return "range"
	case PartitionStrategyRoundRobin:
		return "round_robin"
	case PartitionStrategyCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// BatchOptimization represents batch processing optimization results
type BatchOptimization struct {
	ID              string                  `json:"id"`
	BatchID         string                  `json:"batch_id"`
	BeforeMetrics   BatchMetrics            `json:"before_metrics"`
	AfterMetrics    BatchMetrics            `json:"after_metrics"`
	Improvement     PerformanceImprovement  `json:"improvement"`
	Configuration   BatchConfig             `json:"configuration"`
	Recommendations []Recommendation        `json:"recommendations"`
	OptimizedAt     time.Time               `json:"optimized_at"`
	Status          OptimizationStatus      `json:"status"`
	Cost            OptimizationCost        `json:"cost"`
}

// BatchMetrics represents batch processing metrics
type BatchMetrics struct {
	BatchID           string        `json:"batch_id"`
	Timestamp         time.Time     `json:"timestamp"`
	ProcessedItems    int64         `json:"processed_items"`
	FailedItems       int64         `json:"failed_items"`
	AverageBatchSize  float64       `json:"average_batch_size"`
	ThroughputPerSec  float64       `json:"throughput_per_sec"`
	ProcessingLatency time.Duration `json:"processing_latency"`
	QueueWaitTime     time.Duration `json:"queue_wait_time"`
	SuccessRate       float64       `json:"success_rate"`
	ResourceUsage     ResourceUsage `json:"resource_usage"`
	CostPerItem       float64       `json:"cost_per_item"`
}

// ConnectionConfig configures connection optimization
type ConnectionConfig struct {
	PoolID           string            `json:"pool_id"`
	MaxConnections   int               `json:"max_connections"`
	MinConnections   int               `json:"min_connections"`
	IdleTimeout      time.Duration     `json:"idle_timeout"`
	ConnectionTimeout time.Duration    `json:"connection_timeout"`
	ReadTimeout      time.Duration     `json:"read_timeout"`
	WriteTimeout     time.Duration     `json:"write_timeout"`
	KeepAlive        time.Duration     `json:"keep_alive"`
	RetryCount       int               `json:"retry_count"`
	CircuitBreaker   CircuitBreakerConfig `json:"circuit_breaker"`
	LoadBalancing    LoadBalancingConfig  `json:"load_balancing"`
	Monitoring       MonitoringConfig     `json:"monitoring"`
}

// CircuitBreakerConfig configures circuit breaker behavior
type CircuitBreakerConfig struct {
	Enabled          bool          `json:"enabled"`
	FailureThreshold int           `json:"failure_threshold"`
	RecoveryTimeout  time.Duration `json:"recovery_timeout"`
	SuccessThreshold int           `json:"success_threshold"`
	HalfOpenRequests int           `json:"half_open_requests"`
}

// LoadBalancingConfig configures load balancing
type LoadBalancingConfig struct {
	Strategy      LoadBalanceStrategy `json:"strategy"`
	HealthCheck   HealthCheckConfig   `json:"health_check"`
	StickySession bool                `json:"sticky_session"`
	Weights       map[string]int      `json:"weights"`
}

// LoadBalanceStrategy represents load balancing strategies
type LoadBalanceStrategy int

const (
	LoadBalanceRoundRobin LoadBalanceStrategy = iota
	LoadBalanceLeastConnections
	LoadBalanceWeightedRoundRobin
	LoadBalanceIPHash
	LoadBalanceLeastResponseTime
)

func (l LoadBalanceStrategy) String() string {
	switch l {
	case LoadBalanceRoundRobin:
		return "round_robin"
	case LoadBalanceLeastConnections:
		return "least_connections"
	case LoadBalanceWeightedRoundRobin:
		return "weighted_round_robin"
	case LoadBalanceIPHash:
		return "ip_hash"
	case LoadBalanceLeastResponseTime:
		return "least_response_time"
	default:
		return "unknown"
	}
}

// HealthCheckConfig configures health checking
type HealthCheckConfig struct {
	Enabled         bool          `json:"enabled"`
	Interval        time.Duration `json:"interval"`
	Timeout         time.Duration `json:"timeout"`
	HealthyThreshold int          `json:"healthy_threshold"`
	UnhealthyThreshold int        `json:"unhealthy_threshold"`
	Path            string        `json:"path"`
	Port            int           `json:"port"`
}

// ConnectionOptimization represents connection optimization results
type ConnectionOptimization struct {
	ID              string                  `json:"id"`
	PoolID          string                  `json:"pool_id"`
	BeforeMetrics   ConnectionMetrics       `json:"before_metrics"`
	AfterMetrics    ConnectionMetrics       `json:"after_metrics"`
	Improvement     PerformanceImprovement  `json:"improvement"`
	Configuration   ConnectionConfig        `json:"configuration"`
	Recommendations []Recommendation        `json:"recommendations"`
	OptimizedAt     time.Time               `json:"optimized_at"`
	Status          OptimizationStatus      `json:"status"`
	Cost            OptimizationCost        `json:"cost"`
}

// ConnectionMetrics represents connection pool metrics
type ConnectionMetrics struct {
	PoolID              string        `json:"pool_id"`
	Timestamp           time.Time     `json:"timestamp"`
	ActiveConnections   int           `json:"active_connections"`
	IdleConnections     int           `json:"idle_connections"`
	ConnectionsCreated  int64         `json:"connections_created"`
	ConnectionsDestroyed int64        `json:"connections_destroyed"`
	ConnectionsRefused  int64         `json:"connections_refused"`
	AverageWaitTime     time.Duration `json:"average_wait_time"`
	MaxWaitTime         time.Duration `json:"max_wait_time"`
	ConnectionLatency   time.Duration `json:"connection_latency"`
	UtilizationRate     float64       `json:"utilization_rate"`
	ErrorRate           float64       `json:"error_rate"`
	Efficiency          float64       `json:"efficiency"`
}

// ResourceConfig configures resource optimization
type ResourceConfig struct {
	ResourceID       string              `json:"resource_id"`
	ResourceType     ResourceType        `json:"resource_type"`
	CPUTarget        float64             `json:"cpu_target"`
	MemoryTarget     float64             `json:"memory_target"`
	DiskTarget       float64             `json:"disk_target"`
	NetworkTarget    float64             `json:"network_target"`
	Optimization     OptimizationLevel   `json:"optimization"`
	Policies         []ResourcePolicy    `json:"policies"`
	Constraints      []Constraint        `json:"constraints"`
	Monitoring       MonitoringConfig    `json:"monitoring"`
}

// ResourcePolicy defines resource management policies
type ResourcePolicy struct {
	Type        ResourcePolicyType    `json:"type"`
	Action      PolicyAction          `json:"action"`
	Threshold   float64               `json:"threshold"`
	Duration    time.Duration         `json:"duration"`
	Enabled     bool                  `json:"enabled"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ResourcePolicyType represents resource policy types
type ResourcePolicyType int

const (
	ResourcePolicyCPU ResourcePolicyType = iota
	ResourcePolicyMemory
	ResourcePolicyDisk
	ResourcePolicyNetwork
	ResourcePolicyQuality
)

func (r ResourcePolicyType) String() string {
	switch r {
	case ResourcePolicyCPU:
		return "cpu"
	case ResourcePolicyMemory:
		return "memory"
	case ResourcePolicyDisk:
		return "disk"
	case ResourcePolicyNetwork:
		return "network"
	case ResourcePolicyQuality:
		return "quality"
	default:
		return "unknown"
	}
}

// PolicyAction represents policy actions
type PolicyAction int

const (
	PolicyActionThrottle PolicyAction = iota
	PolicyActionScale
	PolicyActionAlert
	PolicyActionBlock
	PolicyActionOptimize
)

func (p PolicyAction) String() string {
	switch p {
	case PolicyActionThrottle:
		return "throttle"
	case PolicyActionScale:
		return "scale"
	case PolicyActionAlert:
		return "alert"
	case PolicyActionBlock:
		return "block"
	case PolicyActionOptimize:
		return "optimize"
	default:
		return "unknown"
	}
}

// ResourceOptimization represents resource optimization results
type ResourceOptimization struct {
	ID              string                  `json:"id"`
	ResourceID      string                  `json:"resource_id"`
	BeforeMetrics   ResourceMetrics         `json:"before_metrics"`
	AfterMetrics    ResourceMetrics         `json:"after_metrics"`
	Improvement     PerformanceImprovement  `json:"improvement"`
	Configuration   ResourceConfig          `json:"configuration"`
	Recommendations []Recommendation        `json:"recommendations"`
	OptimizedAt     time.Time               `json:"optimized_at"`
	Status          OptimizationStatus      `json:"status"`
	Cost            OptimizationCost        `json:"cost"`
}

// ResourceMetrics represents resource utilization metrics
type ResourceMetrics struct {
	ResourceID       string        `json:"resource_id"`
	Timestamp        time.Time     `json:"timestamp"`
	CPUUsage         float64       `json:"cpu_usage"`
	MemoryUsage      float64       `json:"memory_usage"`
	DiskUsage        float64       `json:"disk_usage"`
	NetworkUsage     float64       `json:"network_usage"`
	CPUEfficiency    float64       `json:"cpu_efficiency"`
	MemoryEfficiency float64       `json:"memory_efficiency"`
	DiskEfficiency   float64       `json:"disk_efficiency"`
	NetworkEfficiency float64      `json:"network_efficiency"`
	CostPerHour      float64       `json:"cost_per_hour"`
	Availability     float64       `json:"availability"`
	OverallScore     float64       `json:"overall_score"`
}

// ProfilingSession represents a performance profiling session
type ProfilingSession struct {
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	StartTime   time.Time         `json:"start_time"`
	Duration    time.Duration     `json:"duration"`
	Status      ProfilingStatus   `json:"status"`
	Type        ProfilingType     `json:"type"`
	Options     ProfilingOptions  `json:"options"`
	Results     *ProfilingResults `json:"results,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// ProfilingStatus represents profiling session status
type ProfilingStatus int

const (
	ProfilingStatusRunning ProfilingStatus = iota
	ProfilingStatusCompleted
	ProfilingStatusFailed
	ProfilingStatusCanceled
)

func (p ProfilingStatus) String() string {
	switch p {
	case ProfilingStatusRunning:
		return "running"
	case ProfilingStatusCompleted:
		return "completed"
	case ProfilingStatusFailed:
		return "failed"
	case ProfilingStatusCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// ProfilingType represents profiling types
type ProfilingType int

const (
	ProfilingTypeCPU ProfilingType = iota
	ProfilingTypeMemory
	ProfilingTypeGoroutine
	ProfilingTypeBlock
	ProfilingTypeMutex
	ProfilingTypeTrace
	ProfilingTypeHeap
)

func (p ProfilingType) String() string {
	switch p {
	case ProfilingTypeCPU:
		return "cpu"
	case ProfilingTypeMemory:
		return "memory"
	case ProfilingTypeGoroutine:
		return "goroutine"
	case ProfilingTypeBlock:
		return "block"
	case ProfilingTypeMutex:
		return "mutex"
	case ProfilingTypeTrace:
		return "trace"
	case ProfilingTypeHeap:
		return "heap"
	default:
		return "unknown"
	}
}

// ProfilingOptions configures profiling behavior
type ProfilingOptions struct {
	SampleRate     int                    `json:"sample_rate"`
	MemProfileRate int                    `json:"mem_profile_rate"`
	BlockProfileRate int                  `json:"block_profile_rate"`
	MutexProfileFraction int              `json:"mutex_profile_fraction"`
	EnableTrace    bool                   `json:"enable_trace"`
	EnableHeap     bool                   `json:"enable_heap"`
	Filters        []string               `json:"filters"`
	Labels         map[string]string      `json:"labels"`
}

// ProfilingResults represents profiling results
type ProfilingResults struct {
	SessionID        string               `json:"session_id"`
	CompletedAt      time.Time            `json:"completed_at"`
	Summary          ProfilingSummary     `json:"summary"`
	HotSpots         []HotSpot            `json:"hot_spots"`
	CallGraph        []CallNode           `json:"call_graph"`
	MemoryProfile    *MemoryProfile       `json:"memory_profile,omitempty"`
	CPUProfile       *CPUProfile          `json:"cpu_profile,omitempty"`
	Recommendations  []Recommendation     `json:"recommendations"`
	Issues           []PerformanceIssue   `json:"issues"`
}

// ProfilingSummary provides high-level profiling summary
type ProfilingSummary struct {
	TotalSamples     int64         `json:"total_samples"`
	Duration         time.Duration `json:"duration"`
	CPUUsage         float64       `json:"cpu_usage"`
	MemoryUsage      int64         `json:"memory_usage"`
	GoroutineCount   int           `json:"goroutine_count"`
	GCPauses         []time.Duration `json:"gc_pauses"`
	AllocRate        float64       `json:"alloc_rate"`
	BlockedTime      time.Duration `json:"blocked_time"`
	MutexWaitTime    time.Duration `json:"mutex_wait_time"`
}

// HotSpot represents a performance hotspot
type HotSpot struct {
	Function     string        `json:"function"`
	File         string        `json:"file"`
	Line         int           `json:"line"`
	CPUTime      time.Duration `json:"cpu_time"`
	CPUPercent   float64       `json:"cpu_percent"`
	Samples      int64         `json:"samples"`
	SelfTime     time.Duration `json:"self_time"`
	CumulativeTime time.Duration `json:"cumulative_time"`
	Callers      []string      `json:"callers"`
	Callees      []string      `json:"callees"`
}

// CallNode represents a node in the call graph
type CallNode struct {
	Function   string     `json:"function"`
	File       string     `json:"file"`
	Line       int        `json:"line"`
	SelfTime   time.Duration `json:"self_time"`
	TotalTime  time.Duration `json:"total_time"`
	CallCount  int64      `json:"call_count"`
	Children   []CallNode `json:"children,omitempty"`
}

// MemoryProfile represents memory profiling data
type MemoryProfile struct {
	TotalAlloc     int64              `json:"total_alloc"`
	Sys            int64              `json:"sys"`
	Lookups        int64              `json:"lookups"`
	Mallocs        int64              `json:"mallocs"`
	Frees          int64              `json:"frees"`
	HeapAlloc      int64              `json:"heap_alloc"`
	HeapSys        int64              `json:"heap_sys"`
	HeapIdle       int64              `json:"heap_idle"`
	HeapInuse      int64              `json:"heap_inuse"`
	HeapReleased   int64              `json:"heap_released"`
	HeapObjects    int64              `json:"heap_objects"`
	StackInuse     int64              `json:"stack_inuse"`
	StackSys       int64              `json:"stack_sys"`
	Allocations    []AllocationSite   `json:"allocations"`
	LeakCandidates []LeakCandidate    `json:"leak_candidates"`
}

// AllocationSite represents a memory allocation site
type AllocationSite struct {
	Function      string `json:"function"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	AllocBytes    int64  `json:"alloc_bytes"`
	AllocObjects  int64  `json:"alloc_objects"`
	InuseBytes    int64  `json:"inuse_bytes"`
	InuseObjects  int64  `json:"inuse_objects"`
}

// LeakCandidate represents a potential memory leak
type LeakCandidate struct {
	Function     string        `json:"function"`
	File         string        `json:"file"`
	Line         int           `json:"line"`
	GrowthRate   float64       `json:"growth_rate"`
	Size         int64         `json:"size"`
	Age          time.Duration `json:"age"`
	Confidence   float64       `json:"confidence"`
}

// CPUProfile represents CPU profiling data
type CPUProfile struct {
	TotalSamples int64       `json:"total_samples"`
	SampleRate   int         `json:"sample_rate"`
	Duration     time.Duration `json:"duration"`
	Functions    []FunctionProfile `json:"functions"`
	TopConsumers []CPUConsumer     `json:"top_consumers"`
}

// FunctionProfile represents function-level CPU profile data
type FunctionProfile struct {
	Name         string        `json:"name"`
	File         string        `json:"file"`
	Samples      int64         `json:"samples"`
	SelfTime     time.Duration `json:"self_time"`
	CumulativeTime time.Duration `json:"cumulative_time"`
	Percentage   float64       `json:"percentage"`
}

// CPUConsumer represents a top CPU consumer
type CPUConsumer struct {
	Function   string        `json:"function"`
	CPUTime    time.Duration `json:"cpu_time"`
	Percentage float64       `json:"percentage"`
	CallCount  int64         `json:"call_count"`
}

// PerformanceIssue represents a detected performance issue
type PerformanceIssue struct {
	ID          string        `json:"id"`
	Type        IssueType     `json:"type"`
	Severity    IssueSeverity `json:"severity"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Function    string        `json:"function"`
	File        string        `json:"file"`
	Line        int           `json:"line"`
	Impact      IssueImpact   `json:"impact"`
	Suggestion  string        `json:"suggestion"`
	DetectedAt  time.Time     `json:"detected_at"`
}

// IssueType represents performance issue types
type IssueType int

const (
	IssueTypeCPUBottleneck IssueType = iota
	IssueTypeMemoryLeak
	IssueTypeGoroutineLeak
	IssueTypeBlockingCall
	IssueTypeHighAllocation
	IssueTypeInefficient
	IssueTypeDeadlock
)

func (i IssueType) String() string {
	switch i {
	case IssueTypeCPUBottleneck:
		return "cpu_bottleneck"
	case IssueTypeMemoryLeak:
		return "memory_leak"
	case IssueTypeGoroutineLeak:
		return "goroutine_leak"
	case IssueTypeBlockingCall:
		return "blocking_call"
	case IssueTypeHighAllocation:
		return "high_allocation"
	case IssueTypeInefficient:
		return "inefficient"
	case IssueTypeDeadlock:
		return "deadlock"
	default:
		return "unknown"
	}
}

// IssueSeverity represents issue severity levels
type IssueSeverity int

const (
	IssueSeverityLow IssueSeverity = iota
	IssueSeverityMedium
	IssueSeverityHigh
	IssueSeverityCritical
)

func (i IssueSeverity) String() string {
	switch i {
	case IssueSeverityLow:
		return "low"
	case IssueSeverityMedium:
		return "medium"
	case IssueSeverityHigh:
		return "high"
	case IssueSeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// IssueImpact represents the impact of a performance issue
type IssueImpact struct {
	LatencyIncrease  time.Duration `json:"latency_increase"`
	ThroughputLoss   float64       `json:"throughput_loss"`
	ResourceWaste    float64       `json:"resource_waste"`
	CostIncrease     float64       `json:"cost_increase"`
	UserExperience   float64       `json:"user_experience"`
}

// LoadTestConfig configures load testing
type LoadTestConfig struct {
	TestID          string            `json:"test_id"`
	Target          string            `json:"target"`
	Duration        time.Duration     `json:"duration"`
	VirtualUsers    int               `json:"virtual_users"`
	RampUpTime      time.Duration     `json:"ramp_up_time"`
	RampDownTime    time.Duration     `json:"ramp_down_time"`
	RequestRate     float64           `json:"request_rate"`
	TestType        LoadTestType      `json:"test_type"`
	Scenarios       []TestScenario    `json:"scenarios"`
	Thresholds      []Threshold       `json:"thresholds"`
	Monitoring      MonitoringConfig  `json:"monitoring"`
}

// LoadTestType represents load test types
type LoadTestType int

const (
	LoadTestTypeLoad LoadTestType = iota
	LoadTestTypeStress
	LoadTestTypeSpike
	LoadTestTypeVolume
	LoadTestTypeEndurance
)

func (l LoadTestType) String() string {
	switch l {
	case LoadTestTypeLoad:
		return "load"
	case LoadTestTypeStress:
		return "stress"
	case LoadTestTypeSpike:
		return "spike"
	case LoadTestTypeVolume:
		return "volume"
	case LoadTestTypeEndurance:
		return "endurance"
	default:
		return "unknown"
	}
}

// TestScenario represents a load test scenario
type TestScenario struct {
	Name        string            `json:"name"`
	Weight      float64           `json:"weight"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Parameters  map[string]string `json:"parameters"`
	Expectations []Expectation    `json:"expectations"`
}

// Expectation represents test expectations
type Expectation struct {
	Metric    string     `json:"metric"`
	Operator  string     `json:"operator"`
	Value     float64    `json:"value"`
	Condition string     `json:"condition"`
}

// Threshold represents performance thresholds
type Threshold struct {
	Metric      string     `json:"metric"`
	Condition   string     `json:"condition"`
	Value       float64    `json:"value"`
	AbortOnFail bool       `json:"abort_on_fail"`
	DelayAbort  time.Duration `json:"delay_abort"`
}

// LoadTestResults represents load test results
type LoadTestResults struct {
	TestID        string             `json:"test_id"`
	StartTime     time.Time          `json:"start_time"`
	EndTime       time.Time          `json:"end_time"`
	Duration      time.Duration      `json:"duration"`
	Summary       LoadTestSummary    `json:"summary"`
	Metrics       []TimeSeriesMetric `json:"metrics"`
	Errors        []TestError        `json:"errors"`
	Thresholds    []ThresholdResult  `json:"thresholds"`
	Passed        bool               `json:"passed"`
	Report        string             `json:"report"`
}

// LoadTestSummary provides high-level test summary
type LoadTestSummary struct {
	TotalRequests    int64         `json:"total_requests"`
	FailedRequests   int64         `json:"failed_requests"`
	RequestRate      float64       `json:"request_rate"`
	AvgResponseTime  time.Duration `json:"avg_response_time"`
	P95ResponseTime  time.Duration `json:"p95_response_time"`
	P99ResponseTime  time.Duration `json:"p99_response_time"`
	MinResponseTime  time.Duration `json:"min_response_time"`
	MaxResponseTime  time.Duration `json:"max_response_time"`
	Throughput       float64       `json:"throughput"`
	ErrorRate        float64       `json:"error_rate"`
	VirtualUsers     int           `json:"virtual_users"`
}

// TimeSeriesMetric represents time-series metrics
type TimeSeriesMetric struct {
	Name      string      `json:"name"`
	Timestamp time.Time   `json:"timestamp"`
	Value     float64     `json:"value"`
	Tags      map[string]string `json:"tags"`
}

// TestError represents test errors
type TestError struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Endpoint    string    `json:"endpoint"`
	StatusCode  int       `json:"status_code"`
	Count       int64     `json:"count"`
}

// ThresholdResult represents threshold check results
type ThresholdResult struct {
	Threshold Threshold `json:"threshold"`
	Value     float64   `json:"value"`
	Passed    bool      `json:"passed"`
	Message   string    `json:"message"`
}

// BenchmarkConfig configures benchmark testing
type BenchmarkConfig struct {
	BenchmarkID  string            `json:"benchmark_id"`
	Target       string            `json:"target"`
	Iterations   int               `json:"iterations"`
	Duration     time.Duration     `json:"duration"`
	Parallel     int               `json:"parallel"`
	Setup        string            `json:"setup"`
	Teardown     string            `json:"teardown"`
	Benchmarks   []BenchmarkTest   `json:"benchmarks"`
	Comparison   ComparisonConfig  `json:"comparison"`
	Monitoring   MonitoringConfig  `json:"monitoring"`
}

// BenchmarkTest represents individual benchmark test
type BenchmarkTest struct {
	Name        string            `json:"name"`
	Function    string            `json:"function"`
	Parameters  map[string]interface{} `json:"parameters"`
	Iterations  int               `json:"iterations"`
	Timeout     time.Duration     `json:"timeout"`
	Setup       string            `json:"setup"`
	Teardown    string            `json:"teardown"`
}

// ComparisonConfig configures benchmark comparison
type ComparisonConfig struct {
	Enabled      bool              `json:"enabled"`
	Baseline     string            `json:"baseline"`
	Tolerance    float64           `json:"tolerance"`
	Metrics      []string          `json:"metrics"`
	FailOnRegression bool          `json:"fail_on_regression"`
}

// BenchmarkResults represents benchmark results
type BenchmarkResults struct {
	BenchmarkID string              `json:"benchmark_id"`
	StartTime   time.Time           `json:"start_time"`
	EndTime     time.Time           `json:"end_time"`
	Duration    time.Duration       `json:"duration"`
	Summary     BenchmarkSummary    `json:"summary"`
	Results     []BenchmarkResult   `json:"results"`
	Comparison  *ComparisonResult   `json:"comparison,omitempty"`
	Passed      bool                `json:"passed"`
	Report      string              `json:"report"`
}

// BenchmarkSummary provides high-level benchmark summary
type BenchmarkSummary struct {
	TotalTests       int           `json:"total_tests"`
	PassedTests      int           `json:"passed_tests"`
	FailedTests      int           `json:"failed_tests"`
	TotalIterations  int64         `json:"total_iterations"`
	TotalDuration    time.Duration `json:"total_duration"`
	AverageTime      time.Duration `json:"average_time"`
	MemoryAllocated  int64         `json:"memory_allocated"`
	AllocsPerOp      int64         `json:"allocs_per_op"`
	OverallScore     float64       `json:"overall_score"`
}

// BenchmarkResult represents individual benchmark result
type BenchmarkResult struct {
	Name            string        `json:"name"`
	Iterations      int64         `json:"iterations"`
	NsPerOp         int64         `json:"ns_per_op"`
	BytesPerOp      int64         `json:"bytes_per_op"`
	AllocsPerOp     int64         `json:"allocs_per_op"`
	MemBytesPerOp   int64         `json:"mem_bytes_per_op"`
	TotalTime       time.Duration `json:"total_time"`
	TotalAllocs     int64         `json:"total_allocs"`
	TotalBytes      int64         `json:"total_bytes"`
	Passed          bool          `json:"passed"`
	Error           string        `json:"error,omitempty"`
}

// ComparisonResult represents benchmark comparison results
type ComparisonResult struct {
	Baseline    string                   `json:"baseline"`
	Current     string                   `json:"current"`
	Improvements []PerformanceComparison `json:"improvements"`
	Regressions  []PerformanceComparison `json:"regressions"`
	OverallChange float64                `json:"overall_change"`
	Significant   bool                   `json:"significant"`
}

// PerformanceComparison represents a performance comparison
type PerformanceComparison struct {
	Metric       string  `json:"metric"`
	BaselineValue float64 `json:"baseline_value"`
	CurrentValue  float64 `json:"current_value"`
	Change        float64 `json:"change"`
	ChangePercent float64 `json:"change_percent"`
	Significant   bool    `json:"significant"`
	Better        bool    `json:"better"`
}

package attestation

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AttestationMetrics provides metrics for the attestation system
type AttestationMetrics struct {
	// Request metrics
	requestsTotal         *prometheus.CounterVec
	requestDuration       *prometheus.HistogramVec
	requestValidationErrs prometheus.Counter
	
	// Queue metrics
	queueSize            *prometheus.GaugeVec
	queueWaitTime        *prometheus.HistogramVec
	
	// Processing metrics
	processingLatency     *prometheus.HistogramVec
	evidenceSize         *prometheus.HistogramVec
	verificationLatency  *prometheus.HistogramVec
	
	// Cache metrics
	cacheHits            *prometheus.CounterVec
	cacheMisses          *prometheus.CounterVec
	cacheSize            prometheus.Gauge
	
	// Tenant metrics
	tenantQuotaExceeded  *prometheus.CounterVec
	tenantRequestRate    *prometheus.CounterVec
	
	// Worker metrics
	activeWorkers        prometheus.Gauge
	workerUtilization    *prometheus.GaugeVec
	
	// Error metrics
	errorRate            *prometheus.CounterVec
	
	// SLI/SLO metrics
	attestationLatencyTarget prometheus.Gauge
	attestationSuccessRate   prometheus.Gauge
	availabilityTarget       prometheus.Gauge
	throughputTarget         prometheus.Gauge
	
	// Hardware metrics
	tpmOperations        *prometheus.CounterVec
	hardwareErrors       *prometheus.CounterVec
	
	// Policy metrics
	policyEvaluations    *prometheus.CounterVec
	policyViolations     *prometheus.CounterVec
	
	// ML metrics
	anomalyDetections    *prometheus.CounterVec
	modelPredictions     *prometheus.CounterVec
	modelAccuracy        prometheus.Gauge
}

// NewAttestationMetrics creates a new metrics instance
func NewAttestationMetrics() (*AttestationMetrics, error) {
	return &AttestationMetrics{
		requestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_requests_total",
				Help: "Total number of attestation requests",
			},
			[]string{"tenant_id", "status", "qos_level"},
		),
		
		requestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "attestation_request_duration_seconds",
				Help:    "Duration of attestation requests",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~32s
			},
			[]string{"tenant_id", "qos_level"},
		),
		
		requestValidationErrs: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "attestation_request_validation_errors_total",
				Help: "Total number of request validation errors",
			},
		),
		
		queueSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "attestation_queue_size",
				Help: "Current size of attestation queues",
			},
			[]string{"priority"},
		),
		
		queueWaitTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "attestation_queue_wait_time_seconds",
				Help:    "Time requests spend waiting in queue",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"priority"},
		),
		
		processingLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "attestation_processing_latency_seconds",
				Help:    "Latency of attestation processing",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"tenant_id", "qos_level", "evidence_type"},
		),
		
		evidenceSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "attestation_evidence_size_bytes",
				Help:    "Size of attestation evidence",
				Buckets: prometheus.ExponentialBuckets(1024, 2, 20), // 1KB to ~1GB
			},
			[]string{"evidence_type"},
		),
		
		verificationLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "attestation_verification_latency_seconds",
				Help:    "Latency of evidence verification",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"evidence_type", "verifier"},
		),
		
		cacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"tenant_id"},
		),
		
		cacheMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"tenant_id"},
		),
		
		cacheSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_cache_size_entries",
				Help: "Current number of entries in cache",
			},
		),
		
		tenantQuotaExceeded: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_tenant_quota_exceeded_total",
				Help: "Total number of times tenant quota was exceeded",
			},
			[]string{"tenant_id", "quota_type"},
		),
		
		tenantRequestRate: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_tenant_request_rate",
				Help: "Rate of requests per tenant",
			},
			[]string{"tenant_id"},
		),
		
		activeWorkers: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_active_workers",
				Help: "Number of active worker threads",
			},
		),
		
		workerUtilization: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "attestation_worker_utilization",
				Help: "Utilization of worker threads",
			},
			[]string{"worker_id"},
		),
		
		errorRate: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_errors_total",
				Help: "Total number of attestation errors",
			},
			[]string{"error_type", "component"},
		),
		
		attestationLatencyTarget: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_sli_latency_target_seconds",
				Help: "Target latency for attestation SLI",
			},
		),
		
		attestationSuccessRate: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_sli_success_rate",
				Help: "Success rate SLI for attestation",
			},
		),
		
		availabilityTarget: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_slo_availability_target",
				Help: "Availability target SLO",
			},
		),
		
		throughputTarget: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_slo_throughput_target",
				Help: "Throughput target SLO",
			},
		),
		
		tpmOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_tpm_operations_total",
				Help: "Total number of TPM operations",
			},
			[]string{"operation", "status"},
		),
		
		hardwareErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_hardware_errors_total",
				Help: "Total number of hardware errors",
			},
			[]string{"hardware_type", "error_type"},
		),
		
		policyEvaluations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_policy_evaluations_total",
				Help: "Total number of policy evaluations",
			},
			[]string{"policy_id", "decision"},
		),
		
		policyViolations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_policy_violations_total",
				Help: "Total number of policy violations",
			},
			[]string{"policy_id", "rule_id", "severity"},
		),
		
		anomalyDetections: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_anomaly_detections_total",
				Help: "Total number of anomaly detections",
			},
			[]string{"anomaly_type", "severity"},
		),
		
		modelPredictions: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "attestation_ml_predictions_total",
				Help: "Total number of ML model predictions",
			},
			[]string{"model", "prediction"},
		),
		
		modelAccuracy: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "attestation_ml_model_accuracy",
				Help: "Current accuracy of ML models",
			},
		),
	}, nil
}

// Recording methods

func (m *AttestationMetrics) RecordRequestProcessed(tenantID, status string) {
	m.requestsTotal.WithLabelValues(tenantID, status, "").Inc()
}

func (m *AttestationMetrics) RecordRequestDuration(tenantID, qosLevel string, duration time.Duration) {
	m.requestDuration.WithLabelValues(tenantID, qosLevel).Observe(duration.Seconds())
}

func (m *AttestationMetrics) RecordRequestValidationError() {
	m.requestValidationErrs.Inc()
}

func (m *AttestationMetrics) RecordQueueSize(priority string, size int) {
	m.queueSize.WithLabelValues(priority).Set(float64(size))
}

func (m *AttestationMetrics) RecordQueueWaitTime(priority string, waitTime time.Duration) {
	m.queueWaitTime.WithLabelValues(priority).Observe(waitTime.Seconds())
}

func (m *AttestationMetrics) RecordProcessingLatency(tenantID, qosLevel string, latency time.Duration) {
	m.processingLatency.WithLabelValues(tenantID, qosLevel, "").Observe(latency.Seconds())
}

func (m *AttestationMetrics) RecordEvidenceSize(evidenceType string, size int64) {
	m.evidenceSize.WithLabelValues(evidenceType).Observe(float64(size))
}

func (m *AttestationMetrics) RecordVerificationLatency(evidenceType, verifier string, latency time.Duration) {
	m.verificationLatency.WithLabelValues(evidenceType, verifier).Observe(latency.Seconds())
}

func (m *AttestationMetrics) RecordCacheHit(tenantID string) {
	m.cacheHits.WithLabelValues(tenantID).Inc()
}

func (m *AttestationMetrics) RecordCacheMiss(tenantID string) {
	m.cacheMisses.WithLabelValues(tenantID).Inc()
}

func (m *AttestationMetrics) RecordCacheSize(size int) {
	m.cacheSize.Set(float64(size))
}

func (m *AttestationMetrics) RecordQuotaExceeded(tenantID string) {
	m.tenantQuotaExceeded.WithLabelValues(tenantID, "requests").Inc()
}

func (m *AttestationMetrics) RecordTenantRequest(tenantID string) {
	m.tenantRequestRate.WithLabelValues(tenantID).Inc()
}

func (m *AttestationMetrics) RecordActiveWorkers(count int) {
	m.activeWorkers.Set(float64(count))
}

func (m *AttestationMetrics) RecordWorkerUtilization(workerID string, utilization float64) {
	m.workerUtilization.WithLabelValues(workerID).Set(utilization)
}

func (m *AttestationMetrics) RecordError(errorType, component string) {
	m.errorRate.WithLabelValues(errorType, component).Inc()
}

func (m *AttestationMetrics) RecordTPMOperation(operation, status string) {
	m.tpmOperations.WithLabelValues(operation, status).Inc()
}

func (m *AttestationMetrics) RecordHardwareError(hardwareType, errorType string) {
	m.hardwareErrors.WithLabelValues(hardwareType, errorType).Inc()
}

func (m *AttestationMetrics) RecordPolicyEvaluation(policyID string, decision PolicyDecision) {
	m.policyEvaluations.WithLabelValues(policyID, string(decision)).Inc()
}

func (m *AttestationMetrics) RecordPolicyViolation(policyID, ruleID, severity string) {
	m.policyViolations.WithLabelValues(policyID, ruleID, severity).Inc()
}

func (m *AttestationMetrics) RecordAnomalyDetection(anomalyType, severity string) {
	m.anomalyDetections.WithLabelValues(anomalyType, severity).Inc()
}

func (m *AttestationMetrics) RecordMLPrediction(model, prediction string) {
	m.modelPredictions.WithLabelValues(model, prediction).Inc()
}

func (m *AttestationMetrics) SetModelAccuracy(accuracy float64) {
	m.modelAccuracy.Set(accuracy)
}

// SLI/SLO recording methods

func (m *AttestationMetrics) SetAttestationLatencyTarget(target time.Duration) {
	m.attestationLatencyTarget.Set(target.Seconds())
}

func (m *AttestationMetrics) SetAttestationSuccessRate(rate float64) {
	m.attestationSuccessRate.Set(rate)
}

func (m *AttestationMetrics) SetAvailabilityTarget(target float64) {
	m.availabilityTarget.Set(target)
}

func (m *AttestationMetrics) SetThroughputTarget(target float64) {
	m.throughputTarget.Set(target)
}

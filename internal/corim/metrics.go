package corim

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics contains all CoRIM-related Prometheus metrics
type Metrics struct {
	// Profile-related metrics
	ProfilesLoadedTotal       prometheus.Counter
	ProfileDeletedTotal       prometheus.Counter
	ProfilesCurrentTotal      prometheus.Gauge

	// Parsing metrics
	ParseErrorsTotal          prometheus.CounterVec
	ParseDurationSeconds      prometheus.Histogram
	ParsedFilesTotal          prometheus.Counter

	// Validation metrics
	ValidationErrorsTotal     prometheus.CounterVec
	ValidationDurationSeconds prometheus.Histogram

	// Reference value metrics
	ReferenceValuesStoredTotal prometheus.Counter
	ReferenceValuesQueriedTotal prometheus.Counter
	ReferenceValuesCurrentTotal prometheus.Gauge

	// Query performance metrics
	QueryDurationSeconds       prometheus.Histogram
	StorageOperationDuration  prometheus.HistogramVec
	StorageErrorsTotal        prometheus.CounterVec

	// Attestation integration metrics
	AttestationVerificationsTotal     prometheus.CounterVec
	AttestationReferenceLookupsFailed prometheus.Counter
	AttestationReferenceLookupTime    prometheus.Histogram
}

// NewMetrics creates and registers all CoRIM metrics with Prometheus
func NewMetrics(registry prometheus.Registerer) *Metrics {
	if registry == nil {
		registry = prometheus.DefaultRegisterer
	}

	metrics := &Metrics{
		// Profile metrics
		ProfilesLoadedTotal: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_profiles_loaded_total",
			Help: "Total number of CoRIM profiles loaded",
		}),
		ProfileDeletedTotal: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_profiles_deleted_total",
			Help: "Total number of CoRIM profiles deleted",
		}),
		ProfilesCurrentTotal: promauto.With(registry).NewGauge(prometheus.GaugeOpts{
			Name: "corim_profiles_current_total",
			Help: "Current number of CoRIM profiles stored",
		}),

		// Parse metrics
		ParseErrorsTotal: *promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "corim_parse_errors_total",
			Help: "Total number of CoRIM parsing errors by type",
		}, []string{"error_type", "file_type"}),

		ParseDurationSeconds: promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
			Name:    "corim_parse_duration_seconds",
			Help:    "Time spent parsing CoRIM files",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		}),

		ParsedFilesTotal: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_parsed_files_total",
			Help: "Total number of CoRIM files successfully parsed",
		}),

		// Validation metrics
		ValidationErrorsTotal: *promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "corim_validation_errors_total",
			Help: "Total number of CoRIM validation errors by type",
		}, []string{"error_type", "severity"}),

		ValidationDurationSeconds: promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
			Name:    "corim_validation_duration_seconds",
			Help:    "Time spent validating CoRIM structures",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		}),

		// Reference value metrics
		ReferenceValuesStoredTotal: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_reference_values_stored_total",
			Help: "Total number of reference values stored",
		}),

		ReferenceValuesQueriedTotal: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_reference_values_queried_total",
			Help: "Total number of reference value queries",
		}),

		ReferenceValuesCurrentTotal: promauto.With(registry).NewGauge(prometheus.GaugeOpts{
			Name: "corim_reference_values_current_total",
			Help: "Current number of reference values stored",
		}),

		// Query performance metrics
		QueryDurationSeconds: promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
			Name:    "corim_query_duration_seconds",
			Help:    "Time spent executing reference value queries",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		}),

		StorageOperationDuration: *promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "corim_storage_operation_duration_seconds",
			Help:    "Time spent on storage operations by type",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		}, []string{"operation", "status"}),

		StorageErrorsTotal: *promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "corim_storage_errors_total",
			Help: "Total number of storage errors by operation and error type",
		}, []string{"operation", "error_type"}),

		// Attestation integration metrics
		AttestationVerificationsTotal: *promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "corim_attestation_verifications_total",
			Help: "Total number of attestation verifications using CoRIM by result",
		}, []string{"result", "environment_class"}),

		AttestationReferenceLookupsFailed: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "corim_attestation_reference_lookups_failed_total",
			Help: "Total number of failed reference value lookups during attestation",
		}),

		AttestationReferenceLookupTime: promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
			Name:    "corim_attestation_reference_lookup_duration_seconds",
			Help:    "Time spent looking up reference values during attestation",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		}),
	}

	return metrics
}

// Increment methods for counters

// IncProfilesLoaded increments the profiles loaded counter
func (m *Metrics) IncProfilesLoaded() {
	m.ProfilesLoadedTotal.Inc()
}

// IncProfileDeleted increments the profiles deleted counter
func (m *Metrics) IncProfileDeleted() {
	m.ProfileDeletedTotal.Inc()
}

// IncParseErrors increments parse errors counter with labels
func (m *Metrics) IncParseErrors(errorType string) {
	m.ParseErrorsTotal.WithLabelValues(errorType, "cbor").Inc()
}

// IncParsedFiles increments the parsed files counter
func (m *Metrics) IncParsedFiles() {
	m.ParsedFilesTotal.Inc()
}

// IncValidationErrors increments validation errors counter with labels
func (m *Metrics) IncValidationErrors(errorType, severity string) {
	m.ValidationErrorsTotal.WithLabelValues(errorType, severity).Inc()
}

// IncReferenceValuesQueried increments the reference values queried counter
func (m *Metrics) IncReferenceValuesQueried() {
	m.ReferenceValuesQueriedTotal.Inc()
}

// IncStorageErrors increments storage errors counter with labels
func (m *Metrics) IncStorageErrors(operation, errorType string) {
	m.StorageErrorsTotal.WithLabelValues(operation, errorType).Inc()
}

// IncAttestationVerifications increments attestation verifications counter
func (m *Metrics) IncAttestationVerifications(result, environmentClass string) {
	m.AttestationVerificationsTotal.WithLabelValues(result, environmentClass).Inc()
}

// IncAttestationReferenceLookupsFailed increments failed reference lookups counter
func (m *Metrics) IncAttestationReferenceLookupsFailed() {
	m.AttestationReferenceLookupsFailed.Inc()
}

// Set methods for gauges

// SetCurrentProfiles sets the current number of profiles
func (m *Metrics) SetCurrentProfiles(count float64) {
	m.ProfilesCurrentTotal.Set(count)
}

// SetCurrentReferenceValues sets the current number of reference values
func (m *Metrics) SetCurrentReferenceValues(count float64) {
	m.ReferenceValuesCurrentTotal.Set(count)
}

// Add methods for counters that can increment by arbitrary amounts

// AddReferenceValuesStored adds to the reference values stored counter
func (m *Metrics) AddReferenceValuesStored(count float64) {
	m.ReferenceValuesStoredTotal.Add(count)
}

// Observe methods for histograms

// ObserveParseTime observes parse duration
func (m *Metrics) ObserveParseTime(seconds float64) {
	m.ParseDurationSeconds.Observe(seconds)
}

// ObserveValidationTime observes validation duration
func (m *Metrics) ObserveValidationTime(seconds float64) {
	m.ValidationDurationSeconds.Observe(seconds)
}

// ObserveQueryTime observes query duration
func (m *Metrics) ObserveQueryTime(seconds float64) {
	m.QueryDurationSeconds.Observe(seconds)
}

// ObserveStorageOperation observes storage operation duration
func (m *Metrics) ObserveStorageOperation(operation, status string, seconds float64) {
	m.StorageOperationDuration.WithLabelValues(operation, status).Observe(seconds)
}

// ObserveAttestationReferenceLookupTime observes reference lookup time during attestation
func (m *Metrics) ObserveAttestationReferenceLookupTime(seconds float64) {
	m.AttestationReferenceLookupTime.Observe(seconds)
}

// Helper methods for common metric updates

// UpdateProfileCount updates both increment and gauge metrics for profiles
func (m *Metrics) UpdateProfileCount(loaded bool, currentTotal int) {
	if loaded {
		m.IncProfilesLoaded()
	}
	m.SetCurrentProfiles(float64(currentTotal))
}

// UpdateReferenceValueCount updates both increment and gauge metrics for reference values
func (m *Metrics) UpdateReferenceValueCount(added int, currentTotal int) {
	if added > 0 {
		m.AddReferenceValuesStored(float64(added))
	}
	m.SetCurrentReferenceValues(float64(currentTotal))
}

// RecordSuccessfulParse records metrics for a successful parse operation
func (m *Metrics) RecordSuccessfulParse(duration float64) {
	m.IncParsedFiles()
	m.ObserveParseTime(duration)
}

// RecordFailedParse records metrics for a failed parse operation
func (m *Metrics) RecordFailedParse(errorType string, duration float64) {
	m.IncParseErrors(errorType)
	m.ObserveParseTime(duration)
}

// RecordStorageOperation records metrics for a storage operation
func (m *Metrics) RecordStorageOperation(operation string, success bool, duration float64, errorType string) {
	status := "success"
	if !success {
		status = "error"
		m.IncStorageErrors(operation, errorType)
	}
	m.ObserveStorageOperation(operation, status, duration)
}

// RecordAttestationWithCoRIM records metrics for attestation verification using CoRIM
func (m *Metrics) RecordAttestationWithCoRIM(success bool, environmentClass string, lookupTime float64) {
	result := "success"
	if !success {
		result = "failed"
	}
	
	m.IncAttestationVerifications(result, environmentClass)
	m.ObserveAttestationReferenceLookupTime(lookupTime)
}

// GetMetricsSnapshot returns current metric values for monitoring dashboards
func (m *Metrics) GetMetricsSnapshot() map[string]interface{} {
	// Note: In a real implementation, you'd gather current values from Prometheus metrics
	// This is a simplified version for demonstration
	return map[string]interface{}{
		"profiles_loaded_total":       "check prometheus endpoint",
		"reference_values_stored_total": "check prometheus endpoint",
		"parse_errors_total":          "check prometheus endpoint",
		"validation_errors_total":     "check prometheus endpoint",
		"query_duration_avg":          "check prometheus endpoint",
	}
}
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// QueryMetrics executes a metrics query
func (o *DefaultObservabilityManager) QueryMetrics(ctx context.Context, query *MetricsQuery) (*MetricsResult, error) {
	tracer := otel.Tracer("observability")
	ctx, span := tracer.Start(ctx, "query_metrics")
	defer span.End()

	span.SetAttributes(
		attribute.String("query", query.Query),
		attribute.String("time_range", fmt.Sprintf("%v-%v", query.TimeRange.Start, query.TimeRange.End)),
	)

	start := time.Now()
	o.logger.WithFields(logrus.Fields{
		"query":      query.Query,
		"time_range": fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End),
		"step":       query.Step,
	}).Debug("Executing metrics query")

	// Execute Prometheus query
	result, warnings, err := o.prometheusAPI.QueryRange(ctx, query.Query, v1.Range{
		Start: query.TimeRange.Start,
		End:   query.TimeRange.End,
		Step:  query.Step,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute Prometheus query: %w", err)
	}

	// Convert Prometheus result to our format
	metricsResult := &MetricsResult{
		Series:    make([]MetricSeries, 0),
		Timestamp: time.Now(),
		Duration:  time.Since(start),
		Status:    "success",
		Warnings:  warnings,
	}

	if matrix, ok := result.(model.Matrix); ok {
		for _, sample := range matrix {
			series := MetricSeries{
				Name:   string(sample.Metric["__name__"]),
				Labels: make(map[string]string),
				Values: make([]MetricValue, 0, len(sample.Values)),
			}

			// Extract labels
			for label, value := range sample.Metric {
				if label != "__name__" {
					series.Labels[string(label)] = string(value)
				}
			}

			// Extract values and calculate statistics
			var sum, min, max float64
			min = math.Inf(1)
			max = math.Inf(-1)

			for _, value := range sample.Values {
				val := float64(value.Value)
				series.Values = append(series.Values, MetricValue{
					Timestamp: value.Timestamp.Time(),
					Value:     val,
				})

				sum += val
				if val < min {
					min = val
				}
				if val > max {
					max = val
				}
			}

			if len(sample.Values) > 0 {
				series.Min = min
				series.Max = max
				series.Avg = sum / float64(len(sample.Values))
				series.Last = float64(sample.Values[len(sample.Values)-1].Value)
			}

			metricsResult.Series = append(metricsResult.Series, series)
		}
	}

	o.logger.WithFields(logrus.Fields{
		"series_count": len(metricsResult.Series),
		"duration":     metricsResult.Duration,
		"warnings":     len(warnings),
	}).Debug("Metrics query completed")

	return metricsResult, nil
}

// GetMetricHistory retrieves historical data for a specific metric
func (o *DefaultObservabilityManager) GetMetricHistory(ctx context.Context, metric string, timeRange TimeRange) (*MetricHistory, error) {
	query := &MetricsQuery{
		Query:     metric,
		TimeRange: timeRange,
		Step:      time.Minute, // Default step
	}

	result, err := o.QueryMetrics(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get metric history: %w", err)
	}

	// Calculate summary statistics
	summary := MetricSummary{
		Percentiles: make(map[string]float64),
	}

	allValues := make([]float64, 0)
	for _, series := range result.Series {
		for _, value := range series.Values {
			allValues = append(allValues, value.Value)
		}
	}

	if len(allValues) > 0 {
		sort.Float64s(allValues)
		
		summary.Count = len(allValues)
		summary.Min = allValues[0]
		summary.Max = allValues[len(allValues)-1]
		
		// Calculate sum and average
		for _, val := range allValues {
			summary.Sum += val
		}
		summary.Avg = summary.Sum / float64(len(allValues))
		
		// Calculate standard deviation
		var variance float64
		for _, val := range allValues {
			variance += math.Pow(val-summary.Avg, 2)
		}
		summary.StdDev = math.Sqrt(variance / float64(len(allValues)))
		
		// Calculate percentiles
		summary.Percentiles["p50"] = calculatePercentile(allValues, 50)
		summary.Percentiles["p90"] = calculatePercentile(allValues, 90)
		summary.Percentiles["p95"] = calculatePercentile(allValues, 95)
		summary.Percentiles["p99"] = calculatePercentile(allValues, 99)
	}

	return &MetricHistory{
		Metric:    metric,
		TimeRange: timeRange,
		Series:    result.Series,
		Summary:   summary,
	}, nil
}

// GenerateComplianceReport generates a compliance report
func (o *DefaultObservabilityManager) GenerateComplianceReport(ctx context.Context, request *ComplianceReportRequest) (*ComplianceReport, error) {
	tracer := otel.Tracer("observability")
	ctx, span := tracer.Start(ctx, "generate_compliance_report")
	defer span.End()

	span.SetAttributes(
		attribute.String("framework", request.Framework),
		attribute.StringSlice("services", request.Services),
	)

	o.logger.WithFields(logrus.Fields{
		"framework":  request.Framework,
		"services":   request.Services,
		"time_range": fmt.Sprintf("%v to %v", request.TimeRange.Start, request.TimeRange.End),
	}).Info("Generating compliance report")

	report := &ComplianceReport{
		ID:          fmt.Sprintf("report-%d", time.Now().Unix()),
		Framework:   request.Framework,
		TimeRange:   request.TimeRange,
		GeneratedAt: time.Now(),
		NextReview:  time.Now().Add(90 * 24 * time.Hour), // 90 days
	}

	// Generate compliance controls based on framework
	controls := o.generateComplianceControls(request.Framework)
	
	// Assess each control
	violations := make([]ComplianceViolation, 0)
	compliantCount := 0

	for _, control := range controls {
		// Simulate control assessment
		controlResult := o.assessComplianceControl(ctx, control, request)
		
		if controlResult.Status.Status == "compliant" {
			compliantCount++
		} else {
			// Add violations for non-compliant controls
			violation := ComplianceViolation{
				ID:          fmt.Sprintf("violation-%s-%d", control.ID, time.Now().Unix()),
				ControlID:   control.ID,
				Service:     "system", // Default to system level
				Severity:    "medium",
				Description: fmt.Sprintf("Control %s is not compliant", control.Name),
				DetectedAt:  time.Now(),
				Status:      "open",
			}
			violations = append(violations, violation)
		}
	}

	// Calculate compliance summary
	complianceRate := float64(compliantCount) / float64(len(controls)) * 100
	riskScore := (100 - complianceRate) / 100 * 10 // Risk score 0-10

	report.Summary = ComplianceSummary{
		TotalControls:      len(controls),
		CompliantControls:  compliantCount,
		ComplianceRate:     complianceRate,
		RiskScore:          riskScore,
		TotalViolations:    len(violations),
		CriticalViolations: o.countCriticalViolations(violations),
	}

	report.Controls = controls
	report.Violations = violations

	// Generate service-specific compliance
	serviceCompliance := make([]ServiceCompliance, 0)
	for _, service := range request.Services {
		serviceComp := o.generateServiceCompliance(service, controls, violations)
		serviceCompliance = append(serviceCompliance, serviceComp)
	}
	report.Services = serviceCompliance

	// Generate recommendations
	report.Recommendations = o.generateComplianceRecommendations(violations)

	o.logger.WithFields(logrus.Fields{
		"report_id":       report.ID,
		"compliance_rate": complianceRate,
		"violations":      len(violations),
		"controls":        len(controls),
	}).Info("Compliance report generated")

	return report, nil
}

// GetComplianceStatus returns current compliance status
func (o *DefaultObservabilityManager) GetComplianceStatus(ctx context.Context, framework string) (*ComplianceStatus, error) {
	o.logger.WithField("framework", framework).Debug("Getting compliance status")

	// Simulate compliance status retrieval
	status := &ComplianceStatus{
		Status:      "compliant",
		LastUpdated: time.Now(),
		Score:       85.5,
		Details:     fmt.Sprintf("Compliance with %s framework at 85.5%%", framework),
	}

	// Adjust status based on score
	if status.Score < 70 {
		status.Status = "non_compliant"
	} else if status.Score < 85 {
		status.Status = "partially_compliant"
	}

	return status, nil
}

// GetTraceAnalysis analyzes a distributed trace
func (o *DefaultObservabilityManager) GetTraceAnalysis(ctx context.Context, traceID string) (*TraceAnalysis, error) {
	tracer := otel.Tracer("observability")
	ctx, span := tracer.Start(ctx, "get_trace_analysis")
	defer span.End()

	span.SetAttributes(attribute.String("trace_id", traceID))

	o.logger.WithField("trace_id", traceID).Debug("Analyzing trace")

	// For demonstration, create mock trace analysis
	// In a real implementation, this would query Jaeger or similar
	analysis := &TraceAnalysis{
		TraceID:      traceID,
		Duration:     250 * time.Millisecond,
		SpanCount:    15,
		ServiceCount: 5,
		ErrorCount:   1,
		StartTime:    time.Now().Add(-5 * time.Minute),
		EndTime:      time.Now().Add(-5*time.Minute + 250*time.Millisecond),
	}

	// Create mock root span
	analysis.RootSpan = SpanSummary{
		SpanID:    "root-span-001",
		Service:   "api-gateway",
		Operation: "GET /api/v1/users",
		Duration:  250 * time.Millisecond,
		StartTime: analysis.StartTime,
		EndTime:   analysis.EndTime,
		Status:    "ok",
		Tags: map[string]string{
			"http.method": "GET",
			"http.url":    "/api/v1/users",
			"user.id":     "12345",
		},
	}

	// Create critical path
	analysis.CriticalPath = []SpanSummary{
		analysis.RootSpan,
		{
			SpanID:    "span-002",
			ParentID:  "root-span-001",
			Service:   "user-service",
			Operation: "get_user",
			Duration:  120 * time.Millisecond,
			Status:    "ok",
		},
		{
			SpanID:    "span-003",
			ParentID:  "span-002",
			Service:   "database",
			Operation: "SELECT users",
			Duration:  80 * time.Millisecond,
			Status:    "ok",
		},
	}

	// Identify bottlenecks
	analysis.Bottlenecks = []PerformanceIssue{
		{
			Type:        "slow_query",
			Service:     "database",
			Operation:   "SELECT users",
			Description: "Database query taking longer than expected",
			Duration:    80 * time.Millisecond,
			Impact:      "high",
			Suggestion:  "Consider adding database index on user_id column",
		},
	}

	// Create service summaries
	analysis.Services = []ServiceSummary{
		{
			Name:      "api-gateway",
			SpanCount: 1,
			Duration:  250 * time.Millisecond,
			ErrorRate: 0.0,
			Operations: []string{"GET /api/v1/users"},
		},
		{
			Name:      "user-service",
			SpanCount: 3,
			Duration:  120 * time.Millisecond,
			ErrorRate: 0.0,
			Operations: []string{"get_user", "validate_user"},
		},
		{
			Name:      "database",
			SpanCount: 2,
			Duration:  80 * time.Millisecond,
			ErrorRate: 0.0,
			Operations: []string{"SELECT users", "SELECT permissions"},
		},
	}

	o.logger.WithFields(logrus.Fields{
		"trace_id":      traceID,
		"duration":      analysis.Duration,
		"span_count":    analysis.SpanCount,
		"service_count": analysis.ServiceCount,
		"error_count":   analysis.ErrorCount,
	}).Debug("Trace analysis completed")

	return analysis, nil
}

// QueryTraces queries traces based on criteria
func (o *DefaultObservabilityManager) QueryTraces(ctx context.Context, query *TraceQuery) (*TraceQueryResult, error) {
	o.logger.WithFields(logrus.Fields{
		"service":   query.Service,
		"operation": query.Operation,
		"limit":     query.Limit,
	}).Debug("Querying traces")

	// For demonstration, create mock trace results
	traces := []TraceSummary{
		{
			TraceID:       "trace-001",
			RootService:   "api-gateway",
			RootOperation: "GET /api/v1/users",
			Duration:      250 * time.Millisecond,
			SpanCount:     15,
			ServiceCount:  5,
			ErrorCount:    0,
			StartTime:     time.Now().Add(-10 * time.Minute),
		},
		{
			TraceID:       "trace-002",
			RootService:   "api-gateway",
			RootOperation: "POST /api/v1/users",
			Duration:      180 * time.Millisecond,
			SpanCount:     12,
			ServiceCount:  4,
			ErrorCount:    1,
			StartTime:     time.Now().Add(-8 * time.Minute),
		},
	}

	// Filter traces based on query criteria
	filteredTraces := make([]TraceSummary, 0)
	for _, trace := range traces {
		if query.Service != "" && trace.RootService != query.Service {
			continue
		}
		if query.Operation != "" && trace.RootOperation != query.Operation {
			continue
		}
		if query.MinDuration > 0 && trace.Duration < query.MinDuration {
			continue
		}
		if query.MaxDuration > 0 && trace.Duration > query.MaxDuration {
			continue
		}
		if query.HasErrors != nil && *query.HasErrors != (trace.ErrorCount > 0) {
			continue
		}
		
		filteredTraces = append(filteredTraces, trace)
	}

	// Apply limit
	if query.Limit > 0 && len(filteredTraces) > query.Limit {
		filteredTraces = filteredTraces[:query.Limit]
	}

	result := &TraceQueryResult{
		Traces:    filteredTraces,
		Total:     len(filteredTraces),
		Duration:  50 * time.Millisecond, // Mock query duration
		NextToken: "", // No pagination in this mock
	}

	return result, nil
}

// GetServiceMap generates a service topology map
func (o *DefaultObservabilityManager) GetServiceMap(ctx context.Context, timeRange TimeRange) (*ServiceMap, error) {
	o.logger.WithField("time_range", fmt.Sprintf("%v to %v", timeRange.Start, timeRange.End)).Debug("Generating service map")

	// Create mock service map
	serviceMap := &ServiceMap{
		TimeRange:   timeRange,
		GeneratedAt: time.Now(),
	}

	// Define services
	serviceMap.Services = []ServiceNode{
		{
			Name:        "api-gateway",
			Type:        "gateway",
			Version:     "1.2.0",
			Namespace:   "default",
			Health:      "healthy",
			RequestRate: 150.5,
			ErrorRate:   0.02,
			Latency:     25 * time.Millisecond,
			CPU:         45.2,
			Memory:      68.7,
			Labels: map[string]string{
				"app":     "api-gateway",
				"version": "1.2.0",
				"tier":    "frontend",
			},
		},
		{
			Name:        "user-service",
			Type:        "microservice",
			Version:     "2.1.0",
			Namespace:   "default",
			Health:      "healthy",
			RequestRate: 120.3,
			ErrorRate:   0.01,
			Latency:     35 * time.Millisecond,
			CPU:         32.1,
			Memory:      55.4,
			Labels: map[string]string{
				"app":     "user-service",
				"version": "2.1.0",
				"tier":    "backend",
			},
		},
		{
			Name:        "order-service",
			Type:        "microservice",
			Version:     "1.8.5",
			Namespace:   "default",
			Health:      "degraded",
			RequestRate: 95.7,
			ErrorRate:   0.05,
			Latency:     85 * time.Millisecond,
			CPU:         67.8,
			Memory:      82.3,
			Labels: map[string]string{
				"app":     "order-service",
				"version": "1.8.5",
				"tier":    "backend",
			},
		},
		{
			Name:        "database",
			Type:        "database",
			Version:     "13.4",
			Namespace:   "data",
			Health:      "healthy",
			RequestRate: 200.1,
			ErrorRate:   0.001,
			Latency:     12 * time.Millisecond,
			CPU:         28.9,
			Memory:      71.2,
			Labels: map[string]string{
				"app":  "postgresql",
				"tier": "data",
			},
		},
	}

	// Define connections
	serviceMap.Connections = []ServiceEdge{
		{
			Source:      "api-gateway",
			Target:      "user-service",
			Protocol:    "HTTP",
			RequestRate: 75.2,
			ErrorRate:   0.01,
			Latency:     15 * time.Millisecond,
			Status:      "healthy",
		},
		{
			Source:      "api-gateway",
			Target:      "order-service",
			Protocol:    "HTTP",
			RequestRate: 45.8,
			ErrorRate:   0.03,
			Latency:     25 * time.Millisecond,
			Status:      "degraded",
		},
		{
			Source:      "user-service",
			Target:      "database",
			Protocol:    "TCP",
			RequestRate: 95.1,
			ErrorRate:   0.001,
			Latency:     8 * time.Millisecond,
			Status:      "healthy",
		},
		{
			Source:      "order-service",
			Target:      "database",
			Protocol:    "TCP",
			RequestRate: 87.3,
			ErrorRate:   0.002,
			Latency:     10 * time.Millisecond,
			Status:      "healthy",
		},
	}

	// Define clusters
	serviceMap.Clusters = []ServiceCluster{
		{
			Name:     "frontend",
			Services: []string{"api-gateway"},
			Type:     "gateway",
			Health:   "healthy",
		},
		{
			Name:     "backend",
			Services: []string{"user-service", "order-service"},
			Type:     "microservices",
			Health:   "degraded",
		},
		{
			Name:     "data",
			Services: []string{"database"},
			Type:     "persistence",
			Health:   "healthy",
		},
	}

	// Calculate metrics
	serviceMap.Metrics = ServiceMapMetrics{
		TotalServices:     len(serviceMap.Services),
		TotalConnections:  len(serviceMap.Connections),
		AvgLatency:        calculateAvgLatency(serviceMap.Services),
		OverallErrorRate:  calculateOverallErrorRate(serviceMap.Services),
		HealthyServices:   countHealthyServices(serviceMap.Services),
		UnhealthyServices: countUnhealthyServices(serviceMap.Services),
	}

	return serviceMap, nil
}

// GetPerformanceInsights generates performance insights for a service
func (o *DefaultObservabilityManager) GetPerformanceInsights(ctx context.Context, service string, timeRange TimeRange) (*PerformanceInsights, error) {
	o.logger.WithFields(logrus.Fields{
		"service":    service,
		"time_range": fmt.Sprintf("%v to %v", timeRange.Start, timeRange.End),
	}).Debug("Generating performance insights")

	insights := &PerformanceInsights{
		Service:      service,
		TimeRange:    timeRange,
		OverallScore: 85.5,
		GeneratedAt:  time.Now(),
	}

	// Generate performance trends
	insights.Trends = []PerformanceTrend{
		{
			Metric:      "response_time",
			Direction:   "improving",
			Change:      -12.5,
			Period:      24 * time.Hour,
			Confidence:  0.85,
			Description: "Response time has improved by 12.5% over the last 24 hours",
		},
		{
			Metric:      "error_rate",
			Direction:   "degrading",
			Change:      15.2,
			Period:      7 * 24 * time.Hour,
			Confidence:  0.92,
			Description: "Error rate has increased by 15.2% over the last week",
		},
		{
			Metric:      "throughput",
			Direction:   "stable",
			Change:      2.1,
			Period:      24 * time.Hour,
			Confidence:  0.78,
			Description: "Throughput has remained stable with minor fluctuations",
		},
	}

	// Identify bottlenecks
	insights.Bottlenecks = []PerformanceBottleneck{
		{
			Type:        "database_query",
			Component:   "user_lookup",
			Severity:    "medium",
			Impact:      25.3,
			Description: "User lookup queries are taking longer than baseline",
			Frequency:   45,
			Duration:    150 * time.Millisecond,
			Suggestion:  "Consider adding database index on user_email column",
		},
		{
			Type:        "memory_usage",
			Component:   "cache",
			Severity:    "low",
			Impact:      8.7,
			Description: "Memory usage is approaching 80% threshold",
			Frequency:   12,
			Duration:    0, // Not applicable for resource issues
			Suggestion:  "Increase cache eviction frequency or add more memory",
		},
	}

	// Generate optimization recommendations
	insights.Optimizations = []PerformanceOptimization{
		{
			ID:          "opt-001",
			Type:        "database",
			Priority:    "high",
			Title:       "Optimize User Lookup Queries",
			Description: "Add composite index on (user_email, status) to improve query performance",
			Impact:      35.2,
			Effort:      "low",
			Resources:   []string{"database", "development_team"},
			Timeline:    "1-2 days",
		},
		{
			ID:          "opt-002",
			Type:        "caching",
			Priority:    "medium",
			Title:       "Implement Query Result Caching",
			Description: "Cache frequently accessed user data to reduce database load",
			Impact:      22.8,
			Effort:      "medium",
			Resources:   []string{"development_team", "infrastructure_team"},
			Timeline:    "1 week",
		},
	}

	// Set performance baselines
	insights.Baselines = PerformanceBaseline{
		Latency:     45 * time.Millisecond,
		Throughput:  125.5,
		ErrorRate:   0.02,
		CPU:         35.2,
		Memory:      65.8,
		Established: time.Now().Add(-30 * 24 * time.Hour),
		Confidence:  0.88,
	}

	// Generate predictions
	insights.Predictions = []PerformancePrediction{
		{
			Metric:     "latency",
			Value:      52.3,
			Timestamp:  time.Now().Add(24 * time.Hour),
			Confidence: 0.82,
			Model:      "ARIMA",
			Factors:    []string{"increased_load", "database_performance"},
		},
		{
			Metric:     "error_rate",
			Value:      0.035,
			Timestamp:  time.Now().Add(7 * 24 * time.Hour),
			Confidence: 0.75,
			Model:      "Linear Regression",
			Factors:    []string{"code_changes", "infrastructure_changes"},
		},
	}

	return insights, nil
}

// GetSystemHealth returns overall system health
func (o *DefaultObservabilityManager) GetSystemHealth(ctx context.Context) (*SystemHealth, error) {
	o.logger.Debug("Getting system health")

	health := &SystemHealth{
		Status:      "healthy",
		Score:       87.5,
		LastUpdated: time.Now(),
	}

	// Mock service health data
	health.Services = []ServiceHealth{
		{
			Status: "healthy",
			Score:  92.3,
			Checks: []HealthCheck{
				{
					Name:      "http_response",
					Type:      "http",
					Status:    "passing",
					Message:   "HTTP endpoint responding normally",
					Duration:  15 * time.Millisecond,
					LastCheck: time.Now().Add(-30 * time.Second),
					Threshold: 100,
					Value:     15,
				},
			},
			Uptime: 720 * time.Hour, // 30 days
			SLA: SLAStatus{
				Target:      99.9,
				Current:     99.95,
				Period:      "monthly",
				Status:      "meeting",
				ErrorBudget: 0.05,
			},
		},
	}

	// Infrastructure health
	health.Infrastructure = InfraHealth{
		Status:       "healthy",
		Score:        85.2,
		CPU:          45.3,
		Memory:       67.8,
		Disk:         72.1,
		Network:      98.5,
		Nodes:        3,
		HealthyNodes: 3,
	}

	// Security health
	health.Security = SecurityHealth{
		Status:            "healthy",
		Score:             82.7,
		VulnerabilityCount: 5,
		CriticalVulns:     0,
		SecurityScore:     82.7,
		LastScan:          time.Now().Add(-6 * time.Hour),
		ComplianceScore:   85.5,
	}

	// Performance health
	health.Performance = PerformanceHealth{
		Status:      "healthy",
		Score:       88.9,
		AvgLatency:  35 * time.Millisecond,
		ErrorRate:   0.02,
		Throughput:  150.5,
		Bottlenecks: 2,
	}

	// Compliance health
	health.Compliance = ComplianceHealth{
		Status:         "compliant",
		Score:          85.5,
		Framework:      "NIST-800-155",
		ComplianceRate: 85.5,
		Violations:     3,
		LastAudit:      time.Now().Add(-30 * 24 * time.Hour),
	}

	// Alerts summary
	health.Alerts = AlertsSummary{
		Total:    12,
		Critical: 0,
		Warning:  3,
		Info:     9,
		Firing:   2,
		Resolved: 10,
	}

	// Determine overall status
	if health.Score < 70 {
		health.Status = "unhealthy"
	} else if health.Score < 85 {
		health.Status = "degraded"
	}

	return health, nil
}

// Helper functions

func calculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	index := (percentile / 100) * float64(len(values)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	
	if lower == upper {
		return values[lower]
	}
	
	weight := index - float64(lower)
	return values[lower]*(1-weight) + values[upper]*weight
}

func (o *DefaultObservabilityManager) generateComplianceControls(framework string) []ComplianceControl {
	controls := make([]ComplianceControl, 0)
	
	switch framework {
	case "NIST-800-155":
		controls = append(controls, []ComplianceControl{
			{
				ID:          "NIST-800-155-1",
				Name:        "Secure Boot",
				Framework:   framework,
				Category:    "Boot Security",
				Status:      ComplianceStatus{Status: "compliant"},
				Score:       95.0,
				Evidence:    []string{"secure_boot_enabled", "verified_certificates"},
				LastCheck:   time.Now().Add(-1 * time.Hour),
				NextCheck:   time.Now().Add(23 * time.Hour),
			},
			{
				ID:          "NIST-800-155-2",
				Name:        "Platform Attestation",
				Framework:   framework,
				Category:    "Attestation",
				Status:      ComplianceStatus{Status: "compliant"},
				Score:       88.5,
				Evidence:    []string{"tpm_attestation", "measured_boot"},
				LastCheck:   time.Now().Add(-30 * time.Minute),
				NextCheck:   time.Now().Add(23*time.Hour + 30*time.Minute),
			},
		}...)
	case "SOC2":
		controls = append(controls, []ComplianceControl{
			{
				ID:          "SOC2-CC6.1",
				Name:        "Logical Access Controls",
				Framework:   framework,
				Category:    "Access Control",
				Status:      ComplianceStatus{Status: "partially_compliant"},
				Score:       72.0,
				Evidence:    []string{"rbac_implemented", "mfa_enabled"},
				LastCheck:   time.Now().Add(-2 * time.Hour),
				NextCheck:   time.Now().Add(22 * time.Hour),
			},
		}...)
	}
	
	return controls
}

func (o *DefaultObservabilityManager) assessComplianceControl(ctx context.Context, control ComplianceControl, request *ComplianceReportRequest) ComplianceControl {
	// Simulate control assessment
	// In a real implementation, this would evaluate actual compliance metrics
	
	if control.Score >= 85 {
		control.Status = ComplianceStatus{
			Status:      "compliant",
			LastUpdated: time.Now(),
			Score:       control.Score,
			Details:     fmt.Sprintf("Control %s meets compliance requirements", control.Name),
		}
	} else if control.Score >= 70 {
		control.Status = ComplianceStatus{
			Status:      "partially_compliant",
			LastUpdated: time.Now(),
			Score:       control.Score,
			Details:     fmt.Sprintf("Control %s partially meets requirements", control.Name),
		}
	} else {
		control.Status = ComplianceStatus{
			Status:      "non_compliant",
			LastUpdated: time.Now(),
			Score:       control.Score,
			Details:     fmt.Sprintf("Control %s does not meet requirements", control.Name),
		}
	}
	
	return control
}

func (o *DefaultObservabilityManager) countCriticalViolations(violations []ComplianceViolation) int {
	count := 0
	for _, violation := range violations {
		if violation.Severity == "critical" {
			count++
		}
	}
	return count
}

func (o *DefaultObservabilityManager) generateServiceCompliance(service string, controls []ComplianceControl, violations []ComplianceViolation) ServiceCompliance {
	serviceViolations := make([]ComplianceViolation, 0)
	for _, violation := range violations {
		if violation.Service == service || violation.Service == "system" {
			serviceViolations = append(serviceViolations, violation)
		}
	}
	
	// Calculate risk level based on violations
	riskLevel := "low"
	if len(serviceViolations) > 5 {
		riskLevel = "high"
	} else if len(serviceViolations) > 2 {
		riskLevel = "medium"
	}
	
	return ServiceCompliance{
		ServiceName: service,
		Status: ComplianceStatus{
			Status:      "compliant",
			LastUpdated: time.Now(),
			Score:       85.0,
			Details:     fmt.Sprintf("Service %s compliance status", service),
		},
		Controls:   controls,
		Violations: serviceViolations,
		RiskLevel:  riskLevel,
	}
}

func (o *DefaultObservabilityManager) generateComplianceRecommendations(violations []ComplianceViolation) []string {
	recommendations := make([]string, 0)
	
	severityCount := make(map[string]int)
	for _, violation := range violations {
		severityCount[violation.Severity]++
	}
	
	if severityCount["critical"] > 0 {
		recommendations = append(recommendations, "Address critical compliance violations immediately")
	}
	
	if severityCount["high"] > 3 {
		recommendations = append(recommendations, "Implement automated compliance monitoring")
	}
	
	recommendations = append(recommendations, "Schedule quarterly compliance reviews")
	recommendations = append(recommendations, "Enhance security controls and monitoring")
	
	return recommendations
}

func calculateAvgLatency(services []ServiceNode) time.Duration {
	if len(services) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, service := range services {
		total += service.Latency
	}
	
	return total / time.Duration(len(services))
}

func calculateOverallErrorRate(services []ServiceNode) float64 {
	if len(services) == 0 {
		return 0
	}
	
	var total float64
	for _, service := range services {
		total += service.ErrorRate
	}
	
	return total / float64(len(services))
}

func countHealthyServices(services []ServiceNode) int {
	count := 0
	for _, service := range services {
		if service.Health == "healthy" {
			count++
		}
	}
	return count
}

func countUnhealthyServices(services []ServiceNode) int {
	count := 0
	for _, service := range services {
		if service.Health != "healthy" {
			count++
		}
	}
	return count
}

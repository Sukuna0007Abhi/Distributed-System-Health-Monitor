package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// DashboardManager manages Grafana dashboard creation and configuration
type DashboardManager interface {
	// Create enterprise dashboards
	CreateSystemOverviewDashboard(ctx context.Context) (*Dashboard, error)
	CreateSecurityDashboard(ctx context.Context) (*Dashboard, error)
	CreatePerformanceDashboard(ctx context.Context) (*Dashboard, error)
	CreateComplianceDashboard(ctx context.Context) (*Dashboard, error)
	CreateAttestationDashboard(ctx context.Context) (*Dashboard, error)
	
	// Deploy dashboards to Grafana
	DeployDashboard(ctx context.Context, dashboard *Dashboard) error
	UpdateDashboard(ctx context.Context, dashboard *Dashboard) error
	
	// Dashboard templates
	GetDashboardTemplate(dashboardType string) (*DashboardTemplate, error)
	CreateCustomDashboard(ctx context.Context, template *DashboardTemplate, variables map[string]interface{}) (*Dashboard, error)
}

// AlertingManager manages Prometheus alerting rules
type AlertingManager interface {
	// Create enterprise alert rules
	CreateSystemAlerts(ctx context.Context) ([]AlertRule, error)
	CreateSecurityAlerts(ctx context.Context) ([]AlertRule, error)
	CreatePerformanceAlerts(ctx context.Context) ([]AlertRule, error)
	CreateComplianceAlerts(ctx context.Context) ([]AlertRule, error)
	
	// Deploy alerts to Prometheus/Alertmanager
	DeployAlerts(ctx context.Context, alerts []AlertRule) error
	
	// Alert templates
	GetAlertTemplate(alertType string) (*AlertTemplate, error)
	CreateCustomAlert(ctx context.Context, template *AlertTemplate, variables map[string]interface{}) (*AlertRule, error)
}

// DashboardTemplate represents a dashboard template
type DashboardTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Template    string                 `json:"template"` // JSON template with variables
	Variables   []TemplateVariable     `json:"variables"`
	Tags        []string               `json:"tags"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertTemplate represents an alert rule template
type AlertTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Template    string                 `json:"template"` // PromQL template with variables
	Variables   []TemplateVariable     `json:"variables"`
	Severity    AlertSeverity          `json:"severity"`
	For         time.Duration          `json:"for"`
	Tags        []string               `json:"tags"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	CreatedAt   time.Time              `json:"created_at"`
}

// TemplateVariable represents a template variable
type TemplateVariable struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"` // string, number, boolean, list
	Description  string      `json:"description"`
	DefaultValue interface{} `json:"default_value"`
	Required     bool        `json:"required"`
	Options      []string    `json:"options"` // For list type
	Validation   string      `json:"validation"` // Regex pattern
}

// GrafanaClient represents a Grafana API client
type GrafanaClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *logrus.Logger
}

// PrometheusClient represents a Prometheus API client for alerts
type PrometheusClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *logrus.Logger
}

// DefaultDashboardManager implements DashboardManager
type DefaultDashboardManager struct {
	logger         *logrus.Logger
	grafanaClient  *GrafanaClient
	templates      map[string]*DashboardTemplate
	meter          metric.Meter
}

// DefaultAlertingManager implements AlertingManager
type DefaultAlertingManager struct {
	logger           *logrus.Logger
	prometheusClient *PrometheusClient
	templates        map[string]*AlertTemplate
	meter            metric.Meter
}

// NewGrafanaClient creates a new Grafana client
func NewGrafanaClient(baseURL, apiKey string, logger *logrus.Logger) *GrafanaClient {
	return &GrafanaClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// NewPrometheusClient creates a new Prometheus client
func NewPrometheusClient(baseURL string, logger *logrus.Logger) *PrometheusClient {
	return &PrometheusClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// NewDashboardManager creates a new dashboard manager
func NewDashboardManager(grafanaClient *GrafanaClient, logger *logrus.Logger) *DefaultDashboardManager {
	dm := &DefaultDashboardManager{
		logger:        logger,
		grafanaClient: grafanaClient,
		templates:     make(map[string]*DashboardTemplate),
		meter:         otel.Meter("dashboard_manager"),
	}
	
	// Load built-in templates
	dm.loadBuiltinTemplates()
	
	return dm
}

// NewAlertingManager creates a new alerting manager
func NewAlertingManager(prometheusClient *PrometheusClient, logger *logrus.Logger) *DefaultAlertingManager {
	am := &DefaultAlertingManager{
		logger:           logger,
		prometheusClient: prometheusClient,
		templates:        make(map[string]*AlertTemplate),
		meter:            otel.Meter("alerting_manager"),
	}
	
	// Load built-in templates
	am.loadBuiltinTemplates()
	
	return am
}

// CreateSystemOverviewDashboard creates a comprehensive system overview dashboard
func (dm *DefaultDashboardManager) CreateSystemOverviewDashboard(ctx context.Context) (*Dashboard, error) {
	tracer := otel.Tracer("dashboard_manager")
	ctx, span := tracer.Start(ctx, "create_system_overview_dashboard")
	defer span.End()

	dm.logger.Info("Creating system overview dashboard")

	dashboard := &Dashboard{
		ID:          "system-overview",
		Title:       "Enterprise System Overview",
		Description: "Comprehensive view of distributed health monitoring system",
		Tags:        []string{"system", "overview", "enterprise"},
		Version:     1,
		TimeRange: TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		Refresh:   "30s",
		Editable:  true,
		Shared:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// Add variables
	dashboard.Variables = []DashboardVariable{
		{
			Name:       "environment",
			Type:       "query",
			Label:      "Environment",
			Query:      "label_values(up, environment)",
			DataSource: "prometheus",
			Multi:      false,
			Current:    "production",
		},
		{
			Name:       "service",
			Type:       "query",
			Label:      "Service",
			Query:      "label_values(up{environment=\"$environment\"}, service)",
			DataSource: "prometheus",
			Multi:      true,
			IncludeAll: true,
			Current:    "All",
		},
	}

	// Create panels
	panels := []DashboardPanel{
		// System Health Overview
		{
			ID:         1,
			Title:      "System Health Score",
			Type:       "stat",
			Query:      "system_health_score",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 0, Width: 6, Height: 4},
			Options: map[string]interface{}{
				"colorMode": "background",
				"graphMode": "area",
				"justifyMode": "center",
				"orientation": "horizontal",
			},
			Thresholds: []Threshold{
				{Value: 70, Color: "red", Operation: "lt"},
				{Value: 85, Color: "yellow", Operation: "lt"},
				{Value: 100, Color: "green", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// Service Availability
		{
			ID:         2,
			Title:      "Service Availability",
			Type:       "stat",
			Query:      "avg(up{environment=\"$environment\", service=~\"$service\"}) * 100",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 6, Y: 0, Width: 6, Height: 4},
			Options: map[string]interface{}{
				"colorMode": "background",
			},
			Thresholds: []Threshold{
				{Value: 95, Color: "red", Operation: "lt"},
				{Value: 99, Color: "yellow", Operation: "lt"},
				{Value: 100, Color: "green", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// Request Rate
		{
			ID:         3,
			Title:      "Request Rate",
			Type:       "graph",
			Query:      "sum(rate(http_requests_total{environment=\"$environment\", service=~\"$service\"}[5m]))",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 12, Y: 0, Width: 12, Height: 8},
			Options: map[string]interface{}{
				"legend": map[string]interface{}{
					"show": true,
					"placement": "bottom",
				},
			},
			Units: "reqps",
		},
		
		// Error Rate
		{
			ID:         4,
			Title:      "Error Rate",
			Type:       "graph",
			Query:      "sum(rate(http_requests_total{environment=\"$environment\", service=~\"$service\", status=~\"5.*\"}[5m])) / sum(rate(http_requests_total{environment=\"$environment\", service=~\"$service\"}[5m])) * 100",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 4, Width: 12, Height: 4},
			Thresholds: []Threshold{
				{Value: 1, Color: "green", Operation: "lt"},
				{Value: 5, Color: "yellow", Operation: "lt"},
				{Value: 10, Color: "red", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// Response Time
		{
			ID:         5,
			Title:      "Response Time (P95)",
			Type:       "graph",
			Query:      "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{environment=\"$environment\", service=~\"$service\"}[5m])) by (le, service))",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 8, Width: 12, Height: 8},
			Units:      "s",
		},
		
		// Security Alerts
		{
			ID:         6,
			Title:      "Active Security Alerts",
			Type:       "stat",
			Query:      "sum(ALERTS{alertname=~\".*Security.*\", alertstate=\"firing\"})",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 12, Y: 8, Width: 6, Height: 4},
			Thresholds: []Threshold{
				{Value: 0, Color: "green", Operation: "eq"},
				{Value: 1, Color: "yellow", Operation: "gte"},
				{Value: 5, Color: "red", Operation: "gte"},
			},
		},
		
		// Compliance Status
		{
			ID:         7,
			Title:      "Compliance Score",
			Type:       "gauge",
			Query:      "compliance_score{framework=\"nist\"}",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 18, Y: 8, Width: 6, Height: 4},
			Options: map[string]interface{}{
				"min": 0,
				"max": 100,
			},
			Thresholds: []Threshold{
				{Value: 70, Color: "red", Operation: "lt"},
				{Value: 85, Color: "yellow", Operation: "lt"},
				{Value: 100, Color: "green", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// Service Map
		{
			ID:         8,
			Title:      "Service Dependencies",
			Type:       "nodeGraph",
			Query:      "service_dependencies",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 16, Width: 24, Height: 8},
			Options: map[string]interface{}{
				"nodes": map[string]interface{}{
					"mainStatUnit": "reqps",
					"secondaryStatUnit": "percent",
				},
				"edges": map[string]interface{}{
					"mainStatUnit": "reqps",
					"secondaryStatUnit": "ms",
				},
			},
		},
	}

	dashboard.Panels = panels

	span.SetAttributes(
		attribute.String("dashboard_id", dashboard.ID),
		attribute.Int("panel_count", len(panels)),
	)

	dm.logger.WithFields(logrus.Fields{
		"dashboard_id": dashboard.ID,
		"panel_count":  len(panels),
	}).Info("System overview dashboard created")

	return dashboard, nil
}

// CreateSecurityDashboard creates a security-focused dashboard
func (dm *DefaultDashboardManager) CreateSecurityDashboard(ctx context.Context) (*Dashboard, error) {
	dm.logger.Info("Creating security dashboard")

	dashboard := &Dashboard{
		ID:          "security-overview",
		Title:       "Security & Threat Monitoring",
		Description: "Security events, threats, and compliance monitoring",
		Tags:        []string{"security", "threats", "compliance"},
		Version:     1,
		TimeRange: TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		Refresh:   "1m",
		Editable:  true,
		Shared:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// Security-specific panels
	panels := []DashboardPanel{
		// Security Score
		{
			ID:         1,
			Title:      "Overall Security Score",
			Type:       "stat",
			Query:      "security_score_overall",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 0, Width: 6, Height: 4},
			Thresholds: []Threshold{
				{Value: 70, Color: "red", Operation: "lt"},
				{Value: 85, Color: "yellow", Operation: "lt"},
				{Value: 100, Color: "green", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// Failed Login Attempts
		{
			ID:         2,
			Title:      "Failed Authentication Attempts",
			Type:       "graph",
			Query:      "sum(rate(auth_failures_total[5m]))",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 6, Y: 0, Width: 12, Height: 8},
			Units:      "fails/sec",
		},
		
		// Attestation Failures
		{
			ID:         3,
			Title:      "Attestation Failures",
			Type:       "stat",
			Query:      "sum(increase(attestation_failures_total[1h]))",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 18, Y: 0, Width: 6, Height: 4},
			Thresholds: []Threshold{
				{Value: 0, Color: "green", Operation: "eq"},
				{Value: 5, Color: "yellow", Operation: "lt"},
				{Value: 10, Color: "red", Operation: "gte"},
			},
		},
		
		// CVE Dashboard
		{
			ID:         4,
			Title:      "Vulnerability Status",
			Type:       "table",
			Query:      "vulnerability_scanner_results",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 8, Width: 24, Height: 8},
		},
	}

	dashboard.Panels = panels

	return dashboard, nil
}

// CreatePerformanceDashboard creates a performance monitoring dashboard
func (dm *DefaultDashboardManager) CreatePerformanceDashboard(ctx context.Context) (*Dashboard, error) {
	dm.logger.Info("Creating performance dashboard")

	dashboard := &Dashboard{
		ID:          "performance-monitoring",
		Title:       "Performance Analytics & Optimization",
		Description: "Detailed performance metrics and optimization insights",
		Tags:        []string{"performance", "latency", "throughput"},
		Version:     1,
		TimeRange: TimeRange{
			Start: time.Now().Add(-4 * time.Hour),
			End:   time.Now(),
		},
		Refresh:   "15s",
		Editable:  true,
		Shared:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// Performance-specific panels
	panels := []DashboardPanel{
		// Latency Heatmap
		{
			ID:         1,
			Title:      "Response Time Heatmap",
			Type:       "heatmap",
			Query:      "sum(rate(http_request_duration_seconds_bucket[5m])) by (le)",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 0, Width: 24, Height: 8},
			Options: map[string]interface{}{
				"tooltip": map[string]interface{}{
					"show": true,
				},
			},
		},
		
		// Throughput
		{
			ID:         2,
			Title:      "Throughput (RPS)",
			Type:       "graph",
			Query:      "sum(rate(http_requests_total[5m])) by (service)",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 8, Width: 12, Height: 8},
			Units:      "reqps",
		},
		
		// CPU Usage
		{
			ID:         3,
			Title:      "CPU Usage by Service",
			Type:       "graph",
			Query:      "sum(rate(container_cpu_usage_seconds_total[5m])) by (service) * 100",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 12, Y: 8, Width: 12, Height: 8},
			Units:      "percent",
		},
	}

	dashboard.Panels = panels

	return dashboard, nil
}

// CreateAttestationDashboard creates an attestation-specific dashboard
func (dm *DefaultDashboardManager) CreateAttestationDashboard(ctx context.Context) (*Dashboard, error) {
	dm.logger.Info("Creating attestation dashboard")

	dashboard := &Dashboard{
		ID:          "attestation-monitoring",
		Title:       "RATS Attestation Monitoring",
		Description: "Remote attestation procedures and verification status",
		Tags:        []string{"attestation", "rats", "verification"},
		Version:     1,
		TimeRange: TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		Refresh:   "30s",
		Editable:  true,
		Shared:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// Attestation-specific panels
	panels := []DashboardPanel{
		// Attestation Success Rate
		{
			ID:         1,
			Title:      "Attestation Success Rate",
			Type:       "stat",
			Query:      "sum(rate(attestation_verifications_total{result=\"success\"}[5m])) / sum(rate(attestation_verifications_total[5m])) * 100",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 0, Width: 6, Height: 4},
			Thresholds: []Threshold{
				{Value: 95, Color: "red", Operation: "lt"},
				{Value: 99, Color: "yellow", Operation: "lt"},
				{Value: 100, Color: "green", Operation: "gte"},
			},
			Units: "percent",
		},
		
		// TPM Status
		{
			ID:         2,
			Title:      "TPM Attestation Status",
			Type:       "table",
			Query:      "tpm_attestation_status",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 6, Y: 0, Width: 18, Height: 8},
		},
		
		// Evidence Processing Time
		{
			ID:         3,
			Title:      "Evidence Processing Time",
			Type:       "graph",
			Query:      "histogram_quantile(0.95, sum(rate(attestation_processing_duration_seconds_bucket[5m])) by (le))",
			DataSource: "prometheus",
			Position:   PanelPosition{X: 0, Y: 8, Width: 24, Height: 8},
			Units:      "s",
		},
	}

	dashboard.Panels = panels

	return dashboard, nil
}

// DeployDashboard deploys a dashboard to Grafana
func (dm *DefaultDashboardManager) DeployDashboard(ctx context.Context, dashboard *Dashboard) error {
	dm.logger.WithField("dashboard_id", dashboard.ID).Info("Deploying dashboard to Grafana")

	// Convert to Grafana format
	grafanaDashboard := dm.convertToGrafanaFormat(dashboard)

	// Create request payload
	payload := map[string]interface{}{
		"dashboard": grafanaDashboard,
		"overwrite": true,
		"message":   fmt.Sprintf("Deployed dashboard %s", dashboard.Title),
	}

	return dm.grafanaClient.createOrUpdateDashboard(payload)
}

// CreateSystemAlerts creates system-level alert rules
func (am *DefaultAlertingManager) CreateSystemAlerts(ctx context.Context) ([]AlertRule, error) {
	am.logger.Info("Creating system alert rules")

	alerts := []AlertRule{
		{
			ID:          "high-error-rate",
			Name:        "High Error Rate",
			Description: "Error rate is above threshold",
			Query:       "sum(rate(http_requests_total{status=~\"5.*\"}[5m])) / sum(rate(http_requests_total[5m])) * 100 > 5",
			Condition: AlertCondition{
				Operator:  "gt",
				Threshold: 5,
				Reducer:   "avg",
				TimeRange: "5m",
			},
			Frequency: 1 * time.Minute,
			For:       2 * time.Minute,
			Severity:  SeverityError,
			Labels: map[string]string{
				"team":     "sre",
				"category": "performance",
			},
			Annotations: map[string]string{
				"summary":     "High error rate detected",
				"description": "Error rate is {{ $value }}% which is above the 5% threshold",
			},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			State:     AlertStateOK,
		},
		
		{
			ID:          "service-down",
			Name:        "Service Down",
			Description: "Service is not responding",
			Query:       "up == 0",
			Condition: AlertCondition{
				Operator:  "eq",
				Threshold: 0,
				Reducer:   "last",
				TimeRange: "1m",
			},
			Frequency: 30 * time.Second,
			For:       1 * time.Minute,
			Severity:  SeverityCritical,
			Labels: map[string]string{
				"team":     "sre",
				"category": "availability",
			},
			Annotations: map[string]string{
				"summary":     "Service is down",
				"description": "Service {{ $labels.service }} is not responding",
			},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			State:     AlertStateOK,
		},
		
		{
			ID:          "high-latency",
			Name:        "High Response Latency",
			Description: "Response time is above threshold",
			Query:       "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 0.5",
			Condition: AlertCondition{
				Operator:  "gt",
				Threshold: 0.5,
				Reducer:   "avg",
				TimeRange: "5m",
			},
			Frequency: 1 * time.Minute,
			For:       3 * time.Minute,
			Severity:  SeverityWarning,
			Labels: map[string]string{
				"team":     "sre",
				"category": "performance",
			},
			Annotations: map[string]string{
				"summary":     "High response latency",
				"description": "95th percentile latency is {{ $value }}s which is above 500ms threshold",
			},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			State:     AlertStateOK,
		},
	}

	am.logger.WithField("alert_count", len(alerts)).Info("System alert rules created")

	return alerts, nil
}

// CreateSecurityAlerts creates security-focused alert rules
func (am *DefaultAlertingManager) CreateSecurityAlerts(ctx context.Context) ([]AlertRule, error) {
	am.logger.Info("Creating security alert rules")

	alerts := []AlertRule{
		{
			ID:          "attestation-failure",
			Name:        "Attestation Verification Failed",
			Description: "TPM or hardware attestation verification failed",
			Query:       "increase(attestation_failures_total[5m]) > 0",
			Condition: AlertCondition{
				Operator:  "gt",
				Threshold: 0,
				Reducer:   "sum",
				TimeRange: "5m",
			},
			Frequency: 1 * time.Minute,
			For:       0, // Immediate alert
			Severity:  SeverityCritical,
			Labels: map[string]string{
				"team":     "security",
				"category": "attestation",
			},
			Annotations: map[string]string{
				"summary":     "Attestation verification failed",
				"description": "{{ $value }} attestation verification failures in the last 5 minutes",
			},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			State:     AlertStateOK,
		},
		
		{
			ID:          "suspicious-login-activity",
			Name:        "Suspicious Login Activity",
			Description: "High number of failed login attempts",
			Query:       "sum(rate(auth_failures_total[5m])) > 10",
			Condition: AlertCondition{
				Operator:  "gt",
				Threshold: 10,
				Reducer:   "sum",
				TimeRange: "5m",
			},
			Frequency: 1 * time.Minute,
			For:       2 * time.Minute,
			Severity:  SeverityError,
			Labels: map[string]string{
				"team":     "security",
				"category": "authentication",
			},
			Annotations: map[string]string{
				"summary":     "Suspicious login activity detected",
				"description": "{{ $value }} failed login attempts per second over the last 5 minutes",
			},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			State:     AlertStateOK,
		},
	}

	return alerts, nil
}

// Helper methods

func (dm *DefaultDashboardManager) loadBuiltinTemplates() {
	// Load built-in dashboard templates
	// This would typically load from embedded files or external sources
	dm.logger.Info("Loading built-in dashboard templates")
}

func (am *DefaultAlertingManager) loadBuiltinTemplates() {
	// Load built-in alert templates
	am.logger.Info("Loading built-in alert templates")
}

func (dm *DefaultDashboardManager) convertToGrafanaFormat(dashboard *Dashboard) map[string]interface{} {
	// Convert our dashboard format to Grafana's JSON format
	// This is a simplified conversion - real implementation would be more complex
	
	panels := make([]map[string]interface{}, len(dashboard.Panels))
	for i, panel := range dashboard.Panels {
		panels[i] = map[string]interface{}{
			"id":          panel.ID,
			"title":       panel.Title,
			"type":        panel.Type,
			"targets": []map[string]interface{}{
				{
					"expr":    panel.Query,
					"refId":   "A",
					"datasource": panel.DataSource,
				},
			},
			"gridPos": map[string]interface{}{
				"x": panel.Position.X,
				"y": panel.Position.Y,
				"w": panel.Position.Width,
				"h": panel.Position.Height,
			},
			"options":    panel.Options,
			"fieldConfig": map[string]interface{}{
				"defaults": map[string]interface{}{
					"unit": panel.Units,
					"thresholds": map[string]interface{}{
						"steps": convertThresholds(panel.Thresholds),
					},
				},
			},
		}
	}

	return map[string]interface{}{
		"id":          dashboard.ID,
		"title":       dashboard.Title,
		"description": dashboard.Description,
		"tags":        dashboard.Tags,
		"version":     dashboard.Version,
		"panels":      panels,
		"templating": map[string]interface{}{
			"list": convertVariables(dashboard.Variables),
		},
		"time": map[string]interface{}{
			"from": dashboard.TimeRange.Start.Format(time.RFC3339),
			"to":   dashboard.TimeRange.End.Format(time.RFC3339),
		},
		"refresh":  dashboard.Refresh,
		"editable": dashboard.Editable,
	}
}

func convertThresholds(thresholds []Threshold) []map[string]interface{} {
	steps := make([]map[string]interface{}, len(thresholds))
	for i, threshold := range thresholds {
		steps[i] = map[string]interface{}{
			"color": threshold.Color,
			"value": threshold.Value,
		}
	}
	return steps
}

func convertVariables(variables []DashboardVariable) []map[string]interface{} {
	vars := make([]map[string]interface{}, len(variables))
	for i, variable := range variables {
		vars[i] = map[string]interface{}{
			"name":       variable.Name,
			"type":       variable.Type,
			"label":      variable.Label,
			"query":      variable.Query,
			"datasource": variable.DataSource,
			"multi":      variable.Multi,
			"includeAll": variable.IncludeAll,
			"current": map[string]interface{}{
				"value": variable.Current,
				"text":  variable.Current,
			},
		}
	}
	return vars
}

func (gc *GrafanaClient) createOrUpdateDashboard(payload map[string]interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal dashboard payload: %w", err)
	}

	req, err := http.NewRequest("POST", gc.baseURL+"/api/dashboards/db", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+gc.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Grafana API error: %s", resp.Status)
	}

	gc.logger.Info("Dashboard deployed successfully to Grafana")
	return nil
}

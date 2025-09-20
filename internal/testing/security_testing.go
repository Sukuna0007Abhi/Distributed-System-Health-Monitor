package testing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SecurityTestConfig configures security testing
type SecurityTestConfig struct {
	TestID          string                `json:"test_id"`
	Name            string                `json:"name"`
	Description     string                `json:"description"`
	Target          SecurityTarget        `json:"target"`
	TestSuites      []SecurityTestSuite   `json:"test_suites"`
	Authentication  AuthConfig            `json:"authentication"`
	Scanning        ScanConfig            `json:"scanning"`
	Penetration     PenetrationConfig     `json:"penetration"`
	Compliance      ComplianceConfig      `json:"compliance"`
	Reporting       SecurityReportConfig  `json:"reporting"`
	Environment     map[string]string     `json:"environment"`
	Timeout         time.Duration         `json:"timeout"`
}

// SecurityTarget defines security test targets
type SecurityTarget struct {
	Type         TargetType            `json:"type"`
	Endpoints    []EndpointConfig      `json:"endpoints"`
	Services     []ServiceConfig       `json:"services"`
	Infrastructure []InfraConfig       `json:"infrastructure"`
	APIs         []APIConfig           `json:"apis"`
	Networks     []NetworkConfig       `json:"networks"`
	Databases    []DatabaseConfig      `json:"databases"`
}

// EndpointConfig configures endpoint security testing
type EndpointConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Parameters  map[string]string `json:"parameters"`
	Body        string            `json:"body"`
	TLS         TLSConfig         `json:"tls"`
	Auth        AuthConfig        `json:"auth"`
}

// ServiceConfig configures service security testing
type ServiceConfig struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Version     string            `json:"version"`
	Endpoints   []EndpointConfig  `json:"endpoints"`
	Config      map[string]string `json:"config"`
}

// InfraConfig configures infrastructure security testing
type InfraConfig struct {
	Type        string            `json:"type"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	Credentials map[string]string `json:"credentials"`
}

// APIConfig configures API security testing
type APIConfig struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	BaseURL     string            `json:"base_url"`
	Spec        string            `json:"spec"`
	Endpoints   []EndpointConfig  `json:"endpoints"`
}

// NetworkConfig configures network security testing
type NetworkConfig struct {
	Subnet      string   `json:"subnet"`
	Hosts       []string `json:"hosts"`
	Ports       []int    `json:"ports"`
	Protocols   []string `json:"protocols"`
}

// DatabaseConfig configures database security testing
type DatabaseConfig struct {
	Type        string            `json:"type"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Database    string            `json:"database"`
	Credentials map[string]string `json:"credentials"`
	Schema      string            `json:"schema"`
}

// TLSConfig configures TLS testing
type TLSConfig struct {
	Enabled             bool     `json:"enabled"`
	VerifyCertificates  bool     `json:"verify_certificates"`
	MinVersion          string   `json:"min_version"`
	CipherSuites        []string `json:"cipher_suites"`
	HSTS                bool     `json:"hsts"`
	CertificatePinning  bool     `json:"certificate_pinning"`
}

// AuthConfig configures authentication testing
type AuthConfig struct {
	Type        AuthType          `json:"type"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	Token       string            `json:"token"`
	Certificate string            `json:"certificate"`
	Key         string            `json:"key"`
	Headers     map[string]string `json:"headers"`
}

// AuthType represents authentication types
type AuthType int

const (
	AuthTypeNone AuthType = iota
	AuthTypeBasic
	AuthTypeBearer
	AuthTypeJWT
	AuthTypeOAuth2
	AuthTypeAPIKey
	AuthTypeCertificate
	AuthTypeCustom
)

func (a AuthType) String() string {
	switch a {
	case AuthTypeNone:
		return "none"
	case AuthTypeBasic:
		return "basic"
	case AuthTypeBearer:
		return "bearer"
	case AuthTypeJWT:
		return "jwt"
	case AuthTypeOAuth2:
		return "oauth2"
	case AuthTypeAPIKey:
		return "api_key"
	case AuthTypeCertificate:
		return "certificate"
	case AuthTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// SecurityTestSuite defines security test suites
type SecurityTestSuite struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Type        SecurityTestType    `json:"type"`
	Tests       []SecurityTest      `json:"tests"`
	Enabled     bool                `json:"enabled"`
	Severity    SeverityLevel       `json:"severity"`
	Category    SecurityCategory    `json:"category"`
}

// SecurityTestType represents security test types
type SecurityTestType int

const (
	SecurityTestTypeVulnerability SecurityTestType = iota
	SecurityTestTypePenetration
	SecurityTestTypeCompliance
	SecurityTestTypeAuthentication
	SecurityTestTypeAuthorization
	SecurityTestTypeEncryption
	SecurityTestTypeInputValidation
	SecurityTestTypeSessionManagement
	SecurityTestTypeConfigReview
	SecurityTestTypeCodeReview
	SecurityTestTypeCustom
)

func (s SecurityTestType) String() string {
	switch s {
	case SecurityTestTypeVulnerability:
		return "vulnerability"
	case SecurityTestTypePenetration:
		return "penetration"
	case SecurityTestTypeCompliance:
		return "compliance"
	case SecurityTestTypeAuthentication:
		return "authentication"
	case SecurityTestTypeAuthorization:
		return "authorization"
	case SecurityTestTypeEncryption:
		return "encryption"
	case SecurityTestTypeInputValidation:
		return "input_validation"
	case SecurityTestTypeSessionManagement:
		return "session_management"
	case SecurityTestTypeConfigReview:
		return "config_review"
	case SecurityTestTypeCodeReview:
		return "code_review"
	case SecurityTestTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// SecurityCategory represents security categories
type SecurityCategory int

const (
	SecurityCategoryOWASP SecurityCategory = iota
	SecurityCategoryNIST
	SecurityCategoryISO27001
	SecurityCategoryPCIDSS
	SecurityCategorySOX
	SecurityCategoryHIPAA
	SecurityCategoryGDPR
	SecurityCategoryCustom
)

func (s SecurityCategory) String() string {
	switch s {
	case SecurityCategoryOWASP:
		return "owasp"
	case SecurityCategoryNIST:
		return "nist"
	case SecurityCategoryISO27001:
		return "iso27001"
	case SecurityCategoryPCIDSS:
		return "pci_dss"
	case SecurityCategorySOX:
		return "sox"
	case SecurityCategoryHIPAA:
		return "hipaa"
	case SecurityCategoryGDPR:
		return "gdpr"
	case SecurityCategoryCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// SecurityTest defines individual security tests
type SecurityTest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        SecurityTestType  `json:"type"`
	Severity    SeverityLevel     `json:"severity"`
	CWE         string            `json:"cwe"`
	CVE         string            `json:"cve"`
	OWASP       string            `json:"owasp"`
	Payload     TestPayload       `json:"payload"`
	Expected    ExpectedResult    `json:"expected"`
	Validation  ValidationRule    `json:"validation"`
	Remediation string            `json:"remediation"`
}

// TestPayload defines test payloads
type TestPayload struct {
	Type        PayloadType       `json:"type"`
	Data        string            `json:"data"`
	Encoding    string            `json:"encoding"`
	Parameters  map[string]string `json:"parameters"`
	Headers     map[string]string `json:"headers"`
	Files       []FilePayload     `json:"files"`
}

// PayloadType represents payload types
type PayloadType int

const (
	PayloadTypeSQL PayloadType = iota
	PayloadTypeXSS
	PayloadTypeXXE
	PayloadTypeSSRF
	PayloadTypeCommandInjection
	PayloadTypeLDAP
	PayloadTypeXPath
	PayloadTypeTemplate
	PayloadTypeDeserialization
	PayloadTypeCustom
)

func (p PayloadType) String() string {
	switch p {
	case PayloadTypeSQL:
		return "sql"
	case PayloadTypeXSS:
		return "xss"
	case PayloadTypeXXE:
		return "xxe"
	case PayloadTypeSSRF:
		return "ssrf"
	case PayloadTypeCommandInjection:
		return "command_injection"
	case PayloadTypeLDAP:
		return "ldap"
	case PayloadTypeXPath:
		return "xpath"
	case PayloadTypeTemplate:
		return "template"
	case PayloadTypeDeserialization:
		return "deserialization"
	case PayloadTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// FilePayload defines file payloads
type FilePayload struct {
	Name     string `json:"name"`
	Content  string `json:"content"`
	MimeType string `json:"mime_type"`
	Size     int64  `json:"size"`
}

// ExpectedResult defines expected test results
type ExpectedResult struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      bool              `json:"error"`
	Blocked    bool              `json:"blocked"`
	Detected   bool              `json:"detected"`
}

// ValidationRule defines validation rules
type ValidationRule struct {
	Type       ValidationType    `json:"type"`
	Pattern    string            `json:"pattern"`
	Contains   []string          `json:"contains"`
	NotContains []string         `json:"not_contains"`
	StatusCodes []int            `json:"status_codes"`
	Headers    map[string]string `json:"headers"`
}

// ValidationType represents validation types
type ValidationType int

const (
	ValidationTypeResponse ValidationType = iota
	ValidationTypeHeader
	ValidationTypeBody
	ValidationTypeStatusCode
	ValidationTypeError
	ValidationTypeTime
	ValidationTypeCustom
)

func (v ValidationType) String() string {
	switch v {
	case ValidationTypeResponse:
		return "response"
	case ValidationTypeHeader:
		return "header"
	case ValidationTypeBody:
		return "body"
	case ValidationTypeStatusCode:
		return "status_code"
	case ValidationTypeError:
		return "error"
	case ValidationTypeTime:
		return "time"
	case ValidationTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// ScanConfig configures vulnerability scanning
type ScanConfig struct {
	Enabled    bool              `json:"enabled"`
	Tools      []ScanTool        `json:"tools"`
	Scope      ScanScope         `json:"scope"`
	Depth      int               `json:"depth"`
	Aggressive bool              `json:"aggressive"`
	Stealth    bool              `json:"stealth"`
	Parallel   int               `json:"parallel"`
}

// ScanTool represents scanning tools
type ScanTool struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
}

// ScanScope defines scanning scope
type ScanScope struct {
	Hosts       []string `json:"hosts"`
	Ports       []int    `json:"ports"`
	Protocols   []string `json:"protocols"`
	Paths       []string `json:"paths"`
	Exclusions  []string `json:"exclusions"`
}

// PenetrationConfig configures penetration testing
type PenetrationConfig struct {
	Enabled     bool              `json:"enabled"`
	Phases      []PenTestPhase    `json:"phases"`
	Tools       []PenTestTool     `json:"tools"`
	Scope       PenTestScope      `json:"scope"`
	Rules       EngagementRules   `json:"rules"`
}

// PenTestPhase represents penetration testing phases
type PenTestPhase struct {
	Name        string            `json:"name"`
	Type        PhaseType         `json:"type"`
	Duration    time.Duration     `json:"duration"`
	Tools       []string          `json:"tools"`
	Objectives  []string          `json:"objectives"`
	Enabled     bool              `json:"enabled"`
}

// PhaseType represents phase types
type PhaseType int

const (
	PhaseTypeReconnaissance PhaseType = iota
	PhaseTypeScanning
	PhaseTypeEnumeration
	PhaseTypeVulnerabilityAssessment
	PhaseTypeExploitation
	PhaseTypePostExploitation
	PhaseTypeReporting
)

func (p PhaseType) String() string {
	switch p {
	case PhaseTypeReconnaissance:
		return "reconnaissance"
	case PhaseTypeScanning:
		return "scanning"
	case PhaseTypeEnumeration:
		return "enumeration"
	case PhaseTypeVulnerabilityAssessment:
		return "vulnerability_assessment"
	case PhaseTypeExploitation:
		return "exploitation"
	case PhaseTypePostExploitation:
		return "post_exploitation"
	case PhaseTypeReporting:
		return "reporting"
	default:
		return "unknown"
	}
}

// PenTestTool represents penetration testing tools
type PenTestTool struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Version     string            `json:"version"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
}

// PenTestScope defines penetration testing scope
type PenTestScope struct {
	InScope     []string `json:"in_scope"`
	OutOfScope  []string `json:"out_of_scope"`
	TimeWindow  TimeWindow `json:"time_window"`
	Limitations []string `json:"limitations"`
}

// TimeWindow defines testing time windows
type TimeWindow struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Days     []string  `json:"days"`
	Hours    []string  `json:"hours"`
	Timezone string    `json:"timezone"`
}

// EngagementRules defines engagement rules
type EngagementRules struct {
	NoDoS             bool     `json:"no_dos"`
	NoSocialEng       bool     `json:"no_social_eng"`
	NoPhysical        bool     `json:"no_physical"`
	DataHandling      []string `json:"data_handling"`
	EscalationPath    []string `json:"escalation_path"`
	EmergencyContact  string   `json:"emergency_contact"`
}

// ComplianceConfig configures compliance testing
type ComplianceConfig struct {
	Enabled     bool                `json:"enabled"`
	Standards   []ComplianceStandard `json:"standards"`
	Frameworks  []ComplianceFramework `json:"frameworks"`
	Controls    []ComplianceControl `json:"controls"`
	Reporting   ComplianceReporting `json:"reporting"`
}

// ComplianceStandard represents compliance standards
type ComplianceStandard struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Controls    []string `json:"controls"`
	Enabled     bool     `json:"enabled"`
}

// ComplianceFramework represents compliance frameworks
type ComplianceFramework struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Domains     []string `json:"domains"`
	Controls    []string `json:"controls"`
	Enabled     bool     `json:"enabled"`
}

// ComplianceControl represents compliance controls
type ComplianceControl struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Type        string   `json:"type"`
	Tests       []string `json:"tests"`
	Enabled     bool     `json:"enabled"`
}

// ComplianceReporting configures compliance reporting
type ComplianceReporting struct {
	Format      []string `json:"format"`
	Template    string   `json:"template"`
	Audience    []string `json:"audience"`
	Frequency   string   `json:"frequency"`
	Distribution []string `json:"distribution"`
}

// SecurityReportConfig configures security reporting
type SecurityReportConfig struct {
	Format      []string          `json:"format"`
	Template    string            `json:"template"`
	Sections    []ReportSection   `json:"sections"`
	Severity    SeverityFilter    `json:"severity"`
	Output      string            `json:"output"`
	Distribution []string         `json:"distribution"`
}

// ReportSection represents report sections
type ReportSection struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Content     []string `json:"content"`
	Enabled     bool     `json:"enabled"`
}

// SeverityFilter filters by severity
type SeverityFilter struct {
	Include []SeverityLevel `json:"include"`
	Exclude []SeverityLevel `json:"exclude"`
	Minimum SeverityLevel   `json:"minimum"`
}

// SecurityTestResults represents security test results
type SecurityTestResults struct {
	TestID        string               `json:"test_id"`
	Name          string               `json:"name"`
	StartTime     time.Time            `json:"start_time"`
	EndTime       time.Time            `json:"end_time"`
	Duration      time.Duration        `json:"duration"`
	Status        TestStatus           `json:"status"`
	Summary       SecurityTestSummary  `json:"summary"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities"`
	ScanResults   []ScanResult         `json:"scan_results"`
	PenTestResults []PenTestResult     `json:"pentest_results"`
	Compliance    ComplianceResult     `json:"compliance"`
	Metrics       SecurityMetrics      `json:"metrics"`
	Artifacts     []TestArtifact       `json:"artifacts"`
	Errors        []TestError          `json:"errors"`
	Report        string               `json:"report"`
}

// SecurityTestSummary provides security test summary
type SecurityTestSummary struct {
	TotalTests          int     `json:"total_tests"`
	PassedTests         int     `json:"passed_tests"`
	FailedTests         int     `json:"failed_tests"`
	CriticalFindings    int     `json:"critical_findings"`
	HighFindings        int     `json:"high_findings"`
	MediumFindings      int     `json:"medium_findings"`
	LowFindings         int     `json:"low_findings"`
	InfoFindings        int     `json:"info_findings"`
	SecurityScore       float64 `json:"security_score"`
	RiskScore           float64 `json:"risk_score"`
	ComplianceScore     float64 `json:"compliance_score"`
}

// Vulnerability represents security vulnerabilities
type Vulnerability struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Severity    SeverityLevel    `json:"severity"`
	Category    VulnCategory     `json:"category"`
	CWE         string           `json:"cwe"`
	CVE         string           `json:"cve"`
	CVSS        CVSSScore        `json:"cvss"`
	OWASP       string           `json:"owasp"`
	Location    VulnLocation     `json:"location"`
	Evidence    []Evidence       `json:"evidence"`
	Impact      ImpactRating     `json:"impact"`
	Likelihood  LikelihoodRating `json:"likelihood"`
	Risk        RiskRating       `json:"risk"`
	Remediation Remediation      `json:"remediation"`
	References  []string         `json:"references"`
	Confirmed   bool             `json:"confirmed"`
	FalsePositive bool           `json:"false_positive"`
}

// VulnCategory represents vulnerability categories
type VulnCategory int

const (
	VulnCategoryInjection VulnCategory = iota
	VulnCategoryBrokenAuth
	VulnCategoryDataExposure
	VulnCategoryXXE
	VulnCategoryBrokenAccess
	VulnCategoryMisconfig
	VulnCategoryXSS
	VulnCategoryDeserialization
	VulnCategoryKnownVulns
	VulnCategoryLogging
	VulnCategorySSRF
	VulnCategoryCustom
)

func (v VulnCategory) String() string {
	switch v {
	case VulnCategoryInjection:
		return "injection"
	case VulnCategoryBrokenAuth:
		return "broken_authentication"
	case VulnCategoryDataExposure:
		return "data_exposure"
	case VulnCategoryXXE:
		return "xxe"
	case VulnCategoryBrokenAccess:
		return "broken_access_control"
	case VulnCategoryMisconfig:
		return "security_misconfiguration"
	case VulnCategoryXSS:
		return "xss"
	case VulnCategoryDeserialization:
		return "insecure_deserialization"
	case VulnCategoryKnownVulns:
		return "known_vulnerabilities"
	case VulnCategoryLogging:
		return "insufficient_logging"
	case VulnCategorySSRF:
		return "ssrf"
	case VulnCategoryCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// CVSSScore represents CVSS scoring
type CVSSScore struct {
	Version    string  `json:"version"`
	Vector     string  `json:"vector"`
	BaseScore  float64 `json:"base_score"`
	TempScore  float64 `json:"temporal_score"`
	EnvScore   float64 `json:"environmental_score"`
	Exploitability float64 `json:"exploitability"`
	Impact     float64 `json:"impact"`
}

// VulnLocation represents vulnerability location
type VulnLocation struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Method     string `json:"method"`
	LineNumber int    `json:"line_number"`
	File       string `json:"file"`
	Function   string `json:"function"`
	Code       string `json:"code"`
}

// Evidence represents vulnerability evidence
type Evidence struct {
	Type        string `json:"type"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	Screenshot  string `json:"screenshot"`
	Log         string `json:"log"`
	Description string `json:"description"`
}

// ImpactRating represents impact ratings
type ImpactRating int

const (
	ImpactLow ImpactRating = iota
	ImpactMedium
	ImpactHigh
	ImpactCritical
)

func (i ImpactRating) String() string {
	switch i {
	case ImpactLow:
		return "low"
	case ImpactMedium:
		return "medium"
	case ImpactHigh:
		return "high"
	case ImpactCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// LikelihoodRating represents likelihood ratings
type LikelihoodRating int

const (
	LikelihoodLow LikelihoodRating = iota
	LikelihoodMedium
	LikelihoodHigh
	LikelihoodCritical
)

func (l LikelihoodRating) String() string {
	switch l {
	case LikelihoodLow:
		return "low"
	case LikelihoodMedium:
		return "medium"
	case LikelihoodHigh:
		return "high"
	case LikelihoodCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RiskRating represents risk ratings
type RiskRating int

const (
	RiskLow RiskRating = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskRating) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Remediation represents remediation information
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Code        string   `json:"code"`
	References  []string `json:"references"`
	Effort      string   `json:"effort"`
	Priority    string   `json:"priority"`
}

// ScanResult represents vulnerability scan results
type ScanResult struct {
	ScanID      string          `json:"scan_id"`
	Tool        string          `json:"tool"`
	Target      string          `json:"target"`
	StartTime   time.Time       `json:"start_time"`
	EndTime     time.Time       `json:"end_time"`
	Duration    time.Duration   `json:"duration"`
	Status      TestStatus      `json:"status"`
	Findings    []Vulnerability `json:"findings"`
	Coverage    ScanCoverage    `json:"coverage"`
	Performance ScanPerformance `json:"performance"`
}

// ScanCoverage represents scan coverage
type ScanCoverage struct {
	Hosts       int     `json:"hosts"`
	Ports       int     `json:"ports"`
	Services    int     `json:"services"`
	URLs        int     `json:"urls"`
	Parameters  int     `json:"parameters"`
	Coverage    float64 `json:"coverage"`
}

// ScanPerformance represents scan performance
type ScanPerformance struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	ResponseTime      time.Duration `json:"response_time"`
	ErrorRate         float64 `json:"error_rate"`
	Timeouts          int     `json:"timeouts"`
	Retries           int     `json:"retries"`
}

// PenTestResult represents penetration test results
type PenTestResult struct {
	PhaseID     string          `json:"phase_id"`
	Phase       PhaseType       `json:"phase"`
	StartTime   time.Time       `json:"start_time"`
	EndTime     time.Time       `json:"end_time"`
	Duration    time.Duration   `json:"duration"`
	Status      TestStatus      `json:"status"`
	Objectives  []Objective     `json:"objectives"`
	Findings    []Vulnerability `json:"findings"`
	Artifacts   []TestArtifact  `json:"artifacts"`
	Notes       string          `json:"notes"`
}

// Objective represents penetration test objectives
type Objective struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Status      TestStatus  `json:"status"`
	Evidence    []Evidence  `json:"evidence"`
	Notes       string      `json:"notes"`
}

// ComplianceResult represents compliance test results
type ComplianceResult struct {
	Standard    string                `json:"standard"`
	Version     string                `json:"version"`
	Status      TestStatus            `json:"status"`
	Score       float64               `json:"score"`
	Controls    []ControlResult       `json:"controls"`
	Gaps        []ComplianceGap       `json:"gaps"`
	Recommendations []Recommendation  `json:"recommendations"`
}

// ControlResult represents control test results
type ControlResult struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Status      TestStatus  `json:"status"`
	Score       float64     `json:"score"`
	Evidence    []Evidence  `json:"evidence"`
	Findings    []string    `json:"findings"`
	Notes       string      `json:"notes"`
}

// ComplianceGap represents compliance gaps
type ComplianceGap struct {
	ControlID   string        `json:"control_id"`
	Description string        `json:"description"`
	Severity    SeverityLevel `json:"severity"`
	Impact      string        `json:"impact"`
	Remediation string        `json:"remediation"`
}

// Recommendation represents compliance recommendations
type Recommendation struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Priority    string        `json:"priority"`
	Effort      string        `json:"effort"`
	Impact      string        `json:"impact"`
	References  []string      `json:"references"`
}

// SecurityMetrics represents security metrics
type SecurityMetrics struct {
	VulnerabilityMetrics  VulnMetrics      `json:"vulnerability_metrics"`
	ComplianceMetrics     ComplianceMetrics `json:"compliance_metrics"`
	CoverageMetrics       CoverageMetrics   `json:"coverage_metrics"`
	PerformanceMetrics    PerfMetrics       `json:"performance_metrics"`
	TrendMetrics          TrendMetrics      `json:"trend_metrics"`
}

// VulnMetrics represents vulnerability metrics
type VulnMetrics struct {
	TotalVulns      int     `json:"total_vulnerabilities"`
	CriticalVulns   int     `json:"critical_vulnerabilities"`
	HighVulns       int     `json:"high_vulnerabilities"`
	MediumVulns     int     `json:"medium_vulnerabilities"`
	LowVulns        int     `json:"low_vulnerabilities"`
	VulnDensity     float64 `json:"vulnerability_density"`
	MTTR            time.Duration `json:"mttr"`
	FalsePositives  int     `json:"false_positives"`
	TruePositives   int     `json:"true_positives"`
	Accuracy        float64 `json:"accuracy"`
}

// ComplianceMetrics represents compliance metrics
type ComplianceMetrics struct {
	OverallScore    float64           `json:"overall_score"`
	StandardScores  map[string]float64 `json:"standard_scores"`
	ControlsPassed  int               `json:"controls_passed"`
	ControlsFailed  int               `json:"controls_failed"`
	GapCount        int               `json:"gap_count"`
	Maturity        string            `json:"maturity"`
}

// CoverageMetrics represents coverage metrics
type CoverageMetrics struct {
	CodeCoverage    float64 `json:"code_coverage"`
	TestCoverage    float64 `json:"test_coverage"`
	ScanCoverage    float64 `json:"scan_coverage"`
	AssetCoverage   float64 `json:"asset_coverage"`
	ThreatCoverage  float64 `json:"threat_coverage"`
}

// PerfMetrics represents performance metrics
type PerfMetrics struct {
	ScanTime        time.Duration `json:"scan_time"`
	TestTime        time.Duration `json:"test_time"`
	ResponseTime    time.Duration `json:"response_time"`
	Throughput      float64       `json:"throughput"`
	ErrorRate       float64       `json:"error_rate"`
	ResourceUsage   ResourceUsage `json:"resource_usage"`
}

// TrendMetrics represents trend metrics
type TrendMetrics struct {
	VulnTrend       []TrendPoint `json:"vulnerability_trend"`
	ComplianceTrend []TrendPoint `json:"compliance_trend"`
	SecurityTrend   []TrendPoint `json:"security_trend"`
	RiskTrend       []TrendPoint `json:"risk_trend"`
}

// TrendPoint represents a trend data point
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label"`
}

// RunSecurityTest executes security tests
func (tf *DefaultTestingFramework) RunSecurityTest(ctx context.Context, config *SecurityTestConfig) (*SecurityTestResults, error) {
	tracer := otel.Tracer("testing_framework")
	ctx, span := tracer.Start(ctx, "run_security_test")
	defer span.End()

	span.SetAttributes(
		attribute.String("test_id", config.TestID),
		attribute.String("target_type", config.Target.Type.String()),
		attribute.Int("test_suites", len(config.TestSuites)),
	)

	tf.logger.WithFields(logrus.Fields{
		"test_id":     config.TestID,
		"target_type": config.Target.Type.String(),
		"test_suites": len(config.TestSuites),
	}).Info("Starting security test")

	startTime := time.Now()

	results := &SecurityTestResults{
		TestID:         config.TestID,
		Name:           config.Name,
		StartTime:      startTime,
		Status:         TestStatusRunning,
		Vulnerabilities: make([]Vulnerability, 0),
		ScanResults:    make([]ScanResult, 0),
		PenTestResults: make([]PenTestResult, 0),
		Errors:         make([]TestError, 0),
		Artifacts:      make([]TestArtifact, 0),
	}

	tf.mu.Lock()
	tf.securityTests[config.TestID] = results
	tf.mu.Unlock()

	// Execute vulnerability scans
	if config.Scanning.Enabled {
		scanResults, vulnerabilities, err := tf.executeVulnerabilityScans(ctx, config)
		if err != nil {
			tf.logger.WithError(err).Warn("Vulnerability scan execution failed")
		} else {
			results.ScanResults = scanResults
			results.Vulnerabilities = append(results.Vulnerabilities, vulnerabilities...)
		}
	}

	// Execute penetration tests
	if config.Penetration.Enabled {
		penTestResults, vulnerabilities, err := tf.executePenetrationTests(ctx, config)
		if err != nil {
			tf.logger.WithError(err).Warn("Penetration test execution failed")
		} else {
			results.PenTestResults = penTestResults
			results.Vulnerabilities = append(results.Vulnerabilities, vulnerabilities...)
		}
	}

	// Execute security test suites
	for _, suite := range config.TestSuites {
		if suite.Enabled {
			vulnerabilities, err := tf.executeSecurityTestSuite(ctx, &suite, &config.Target)
			if err != nil {
				tf.logger.WithError(err).WithField("suite", suite.ID).Warn("Security test suite execution failed")
			} else {
				results.Vulnerabilities = append(results.Vulnerabilities, vulnerabilities...)
			}
		}
	}

	// Execute compliance tests
	if config.Compliance.Enabled {
		compliance, err := tf.executeComplianceTests(ctx, &config.Compliance, &config.Target)
		if err != nil {
			tf.logger.WithError(err).Warn("Compliance test execution failed")
		} else {
			results.Compliance = *compliance
		}
	}

	endTime := time.Now()
	results.EndTime = endTime
	results.Duration = endTime.Sub(startTime)

	// Calculate metrics and summary
	results.Metrics = tf.calculateSecurityMetrics(results)
	results.Summary = tf.calculateSecuritySummary(results)

	// Determine overall status
	if results.Summary.CriticalFindings > 0 || results.Summary.HighFindings > 10 {
		results.Status = TestStatusFailed
	} else {
		results.Status = TestStatusPassed
	}

	tf.logger.WithFields(logrus.Fields{
		"test_id":           config.TestID,
		"status":            results.Status.String(),
		"duration":          results.Duration,
		"vulnerabilities":   len(results.Vulnerabilities),
		"security_score":    results.Summary.SecurityScore,
	}).Info("Security test completed")

	return results, nil
}

// GetSecurityTestResults retrieves security test results
func (tf *DefaultTestingFramework) GetSecurityTestResults(ctx context.Context, testID string) (*SecurityTestResults, error) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	results, exists := tf.securityTests[testID]
	if !exists {
		return nil, fmt.Errorf("security test results not found for ID: %s", testID)
	}

	return results, nil
}

// Helper methods for security testing

func (tf *DefaultTestingFramework) executeVulnerabilityScans(ctx context.Context, config *SecurityTestConfig) ([]ScanResult, []Vulnerability, error) {
	tf.logger.Info("Executing vulnerability scans")

	scanResults := make([]ScanResult, 0)
	vulnerabilities := make([]Vulnerability, 0)

	for _, tool := range config.Scanning.Tools {
		if !tool.Enabled {
			continue
		}

		scanResult, vulns, err := tf.executeScanTool(ctx, &tool, &config.Target, &config.Scanning)
		if err != nil {
			tf.logger.WithError(err).WithField("tool", tool.Name).Error("Scan tool execution failed")
			continue
		}

		scanResults = append(scanResults, *scanResult)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return scanResults, vulnerabilities, nil
}

func (tf *DefaultTestingFramework) executeScanTool(ctx context.Context, tool *ScanTool, target *SecurityTarget, config *ScanConfig) (*ScanResult, []Vulnerability, error) {
	tf.logger.WithField("tool", tool.Name).Info("Executing scan tool")

	startTime := time.Now()

	// For demonstration, create mock scan results based on tool type
	var vulnerabilities []Vulnerability
	
	switch strings.ToLower(tool.Name) {
	case "nmap":
		vulnerabilities = tf.generateNetworkVulnerabilities()
	case "nikto":
		vulnerabilities = tf.generateWebVulnerabilities()
	case "sqlmap":
		vulnerabilities = tf.generateSQLInjectionVulnerabilities()
	case "burp":
		vulnerabilities = tf.generateWebAppVulnerabilities()
	default:
		vulnerabilities = tf.generateGenericVulnerabilities()
	}

	endTime := time.Now()

	scanResult := &ScanResult{
		ScanID:    fmt.Sprintf("scan-%s-%d", tool.Name, time.Now().Unix()),
		Tool:      tool.Name,
		Target:    "mock-target",
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
		Status:    TestStatusPassed,
		Findings:  vulnerabilities,
		Coverage: ScanCoverage{
			Hosts:      5,
			Ports:      100,
			Services:   25,
			URLs:       50,
			Parameters: 200,
			Coverage:   85.0,
		},
		Performance: ScanPerformance{
			RequestsPerSecond: 10.0,
			ResponseTime:      250 * time.Millisecond,
			ErrorRate:         2.5,
			Timeouts:          5,
			Retries:           10,
		},
	}

	return scanResult, vulnerabilities, nil
}

func (tf *DefaultTestingFramework) executePenetrationTests(ctx context.Context, config *SecurityTestConfig) ([]PenTestResult, []Vulnerability, error) {
	tf.logger.Info("Executing penetration tests")

	penTestResults := make([]PenTestResult, 0)
	vulnerabilities := make([]Vulnerability, 0)

	for _, phase := range config.Penetration.Phases {
		if !phase.Enabled {
			continue
		}

		result, vulns, err := tf.executePenTestPhase(ctx, &phase, &config.Target)
		if err != nil {
			tf.logger.WithError(err).WithField("phase", phase.Name).Error("Penetration test phase execution failed")
			continue
		}

		penTestResults = append(penTestResults, *result)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return penTestResults, vulnerabilities, nil
}

func (tf *DefaultTestingFramework) executePenTestPhase(ctx context.Context, phase *PenTestPhase, target *SecurityTarget) (*PenTestResult, []Vulnerability, error) {
	tf.logger.WithField("phase", phase.Name).Info("Executing penetration test phase")

	startTime := time.Now()

	// For demonstration, create mock penetration test results
	vulnerabilities := tf.generatePenTestVulnerabilities(phase.Type)

	// Mock objectives based on phase type
	objectives := []Objective{
		{
			ID:          fmt.Sprintf("obj-%s-1", phase.Type.String()),
			Description: fmt.Sprintf("Primary objective for %s phase", phase.Type.String()),
			Status:      TestStatusPassed,
			Evidence:    []Evidence{},
			Notes:       "Objective completed successfully",
		},
	}

	endTime := time.Now()

	result := &PenTestResult{
		PhaseID:     fmt.Sprintf("phase-%s-%d", phase.Type.String(), time.Now().Unix()),
		Phase:       phase.Type,
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    endTime.Sub(startTime),
		Status:      TestStatusPassed,
		Objectives:  objectives,
		Findings:    vulnerabilities,
		Artifacts:   []TestArtifact{},
		Notes:       fmt.Sprintf("Completed %s phase successfully", phase.Type.String()),
	}

	return result, vulnerabilities, nil
}

func (tf *DefaultTestingFramework) executeSecurityTestSuite(ctx context.Context, suite *SecurityTestSuite, target *SecurityTarget) ([]Vulnerability, error) {
	tf.logger.WithField("suite", suite.Name).Info("Executing security test suite")

	vulnerabilities := make([]Vulnerability, 0)

	for _, test := range suite.Tests {
		vuln, err := tf.executeSecurityTest(ctx, &test, target)
		if err != nil {
			tf.logger.WithError(err).WithField("test", test.ID).Error("Security test execution failed")
			continue
		}

		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	return vulnerabilities, nil
}

func (tf *DefaultTestingFramework) executeSecurityTest(ctx context.Context, test *SecurityTest, target *SecurityTarget) (*Vulnerability, error) {
	tf.logger.WithField("test", test.Name).Debug("Executing security test")

	// For demonstration, simulate test execution with some randomness
	if len(target.Endpoints) == 0 {
		return nil, nil // No vulnerability found
	}

	endpoint := target.Endpoints[0]

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute test payload
	req, err := tf.createTestRequest(test, &endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Validate response
	vulnerable := tf.validateTestResponse(test, resp, string(body))
	if !vulnerable {
		return nil, nil
	}

	// Create vulnerability record
	vulnerability := &Vulnerability{
		ID:          fmt.Sprintf("vuln-%s-%d", test.ID, time.Now().Unix()),
		Title:       test.Name,
		Description: test.Description,
		Severity:    test.Severity,
		Category:    VulnCategoryInjection, // Default category
		CWE:         test.CWE,
		CVE:         test.CVE,
		OWASP:       test.OWASP,
		Location: VulnLocation{
			URL:       endpoint.URL,
			Parameter: "test_param",
			Method:    endpoint.Method,
		},
		Evidence: []Evidence{
			{
				Type:        "http",
				Request:     fmt.Sprintf("%s %s", req.Method, req.URL),
				Response:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, string(body)),
				Description: "Test evidence",
			},
		},
		Impact:      ImpactMedium,
		Likelihood:  LikelihoodMedium,
		Risk:        RiskMedium,
		Remediation: Remediation{
			Description: test.Remediation,
			Steps:       []string{"Step 1", "Step 2"},
			Priority:    "Medium",
		},
		Confirmed: true,
	}

	return vulnerability, nil
}

func (tf *DefaultTestingFramework) createTestRequest(test *SecurityTest, endpoint *EndpointConfig) (*http.Request, error) {
	var body io.Reader
	if test.Payload.Data != "" {
		body = strings.NewReader(test.Payload.Data)
	}

	req, err := http.NewRequest(endpoint.Method, endpoint.URL, body)
	if err != nil {
		return nil, err
	}

	// Add headers
	for key, value := range endpoint.Headers {
		req.Header.Set(key, value)
	}
	for key, value := range test.Payload.Headers {
		req.Header.Set(key, value)
	}

	// Add authentication
	if endpoint.Auth.Type != AuthTypeNone {
		tf.addAuthentication(req, &endpoint.Auth)
	}

	return req, nil
}

func (tf *DefaultTestingFramework) addAuthentication(req *http.Request, auth *AuthConfig) {
	switch auth.Type {
	case AuthTypeBasic:
		req.SetBasicAuth(auth.Username, auth.Password)
	case AuthTypeBearer:
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case AuthTypeAPIKey:
		for key, value := range auth.Headers {
			req.Header.Set(key, value)
		}
	}
}

func (tf *DefaultTestingFramework) validateTestResponse(test *SecurityTest, resp *http.Response, body string) bool {
	// Simple validation logic based on test expectations
	validation := &test.Validation

	// Check status codes
	if len(validation.StatusCodes) > 0 {
		found := false
		for _, code := range validation.StatusCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check response contains expected strings
	for _, contains := range validation.Contains {
		if !strings.Contains(body, contains) {
			return false
		}
	}

	// Check response doesn't contain forbidden strings
	for _, notContains := range validation.NotContains {
		if strings.Contains(body, notContains) {
			return false
		}
	}

	return true
}

func (tf *DefaultTestingFramework) executeComplianceTests(ctx context.Context, config *ComplianceConfig, target *SecurityTarget) (*ComplianceResult, error) {
	tf.logger.Info("Executing compliance tests")

	// For demonstration, create mock compliance results
	controls := []ControlResult{
		{
			ID:       "AC-1",
			Name:     "Access Control Policy",
			Status:   TestStatusPassed,
			Score:    85.0,
			Evidence: []Evidence{},
			Findings: []string{"Policy documented", "Regular reviews conducted"},
			Notes:    "Control implemented effectively",
		},
		{
			ID:       "AC-2",
			Name:     "Account Management",
			Status:   TestStatusFailed,
			Score:    60.0,
			Evidence: []Evidence{},
			Findings: []string{"Missing automated provisioning", "Manual deprovisioning process"},
			Notes:    "Improvements needed in automation",
		},
	}

	gaps := []ComplianceGap{
		{
			ControlID:   "AC-2",
			Description: "Automated account provisioning not implemented",
			Severity:    SeverityMedium,
			Impact:      "Manual processes increase risk of errors",
			Remediation: "Implement automated account management system",
		},
	}

	recommendations := []Recommendation{
		{
			ID:          "rec-1",
			Title:       "Implement Account Automation",
			Description: "Deploy automated account provisioning and deprovisioning",
			Priority:    "High",
			Effort:      "Medium",
			Impact:      "High",
			References:  []string{"NIST 800-53 AC-2"},
		},
	}

	result := &ComplianceResult{
		Standard:        "NIST 800-53",
		Version:         "Rev 5",
		Status:          TestStatusPartial,
		Score:           72.5,
		Controls:        controls,
		Gaps:            gaps,
		Recommendations: recommendations,
	}

	return result, nil
}

// Mock vulnerability generators

func (tf *DefaultTestingFramework) generateNetworkVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "vuln-net-001",
			Title:       "Open SSH Port with Weak Configuration",
			Description: "SSH service running with weak cipher suites",
			Severity:    SeverityMedium,
			Category:    VulnCategoryMisconfig,
			Location:    VulnLocation{URL: "tcp://target:22"},
			Confirmed:   true,
		},
	}
}

func (tf *DefaultTestingFramework) generateWebVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "vuln-web-001",
			Title:       "Missing Security Headers",
			Description: "Application missing critical security headers",
			Severity:    SeverityLow,
			Category:    VulnCategoryMisconfig,
			Location:    VulnLocation{URL: "https://target/"},
			Confirmed:   true,
		},
	}
}

func (tf *DefaultTestingFramework) generateSQLInjectionVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "vuln-sql-001",
			Title:       "SQL Injection in Login Form",
			Description: "Login form vulnerable to SQL injection attacks",
			Severity:    SeverityHigh,
			Category:    VulnCategoryInjection,
			CWE:         "CWE-89",
			Location:    VulnLocation{URL: "https://target/login", Parameter: "username"},
			Confirmed:   true,
		},
	}
}

func (tf *DefaultTestingFramework) generateWebAppVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "vuln-xss-001",
			Title:       "Reflected XSS in Search Parameter",
			Description: "Search functionality vulnerable to reflected XSS",
			Severity:    SeverityMedium,
			Category:    VulnCategoryXSS,
			CWE:         "CWE-79",
			OWASP:       "A03:2021",
			Location:    VulnLocation{URL: "https://target/search", Parameter: "q"},
			Confirmed:   true,
		},
	}
}

func (tf *DefaultTestingFramework) generateGenericVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "vuln-gen-001",
			Title:       "Information Disclosure",
			Description: "Application reveals sensitive information in error messages",
			Severity:    SeverityLow,
			Category:    VulnCategoryDataExposure,
			Location:    VulnLocation{URL: "https://target/error"},
			Confirmed:   true,
		},
	}
}

func (tf *DefaultTestingFramework) generatePenTestVulnerabilities(phase PhaseType) []Vulnerability {
	switch phase {
	case PhaseTypeScanning:
		return tf.generateNetworkVulnerabilities()
	case PhaseTypeVulnerabilityAssessment:
		return tf.generateWebAppVulnerabilities()
	case PhaseTypeExploitation:
		return []Vulnerability{
			{
				ID:          "vuln-exploit-001",
				Title:       "Privilege Escalation via Misconfiguration",
				Description: "Service misconfiguration allows privilege escalation",
				Severity:    SeverityHigh,
				Category:    VulnCategoryBrokenAccess,
				Location:    VulnLocation{URL: "system://target"},
				Confirmed:   true,
			},
		}
	default:
		return tf.generateGenericVulnerabilities()
	}
}

func (tf *DefaultTestingFramework) calculateSecurityMetrics(results *SecurityTestResults) SecurityMetrics {
	// Count vulnerabilities by severity
	var critical, high, medium, low int
	for _, vuln := range results.Vulnerabilities {
		switch vuln.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		case SeverityLow:
			low++
		}
	}

	return SecurityMetrics{
		VulnerabilityMetrics: VulnMetrics{
			TotalVulns:     len(results.Vulnerabilities),
			CriticalVulns:  critical,
			HighVulns:      high,
			MediumVulns:    medium,
			LowVulns:       low,
			VulnDensity:    float64(len(results.Vulnerabilities)) / 100.0, // Per 100 assets
			MTTR:           24 * time.Hour,
			FalsePositives: 5,
			TruePositives:  len(results.Vulnerabilities) - 5,
			Accuracy:       95.0,
		},
		ComplianceMetrics: ComplianceMetrics{
			OverallScore:   results.Compliance.Score,
			ControlsPassed: 15,
			ControlsFailed: 3,
			GapCount:       len(results.Compliance.Gaps),
			Maturity:       "Developing",
		},
		CoverageMetrics: CoverageMetrics{
			CodeCoverage:   80.0,
			TestCoverage:   90.0,
			ScanCoverage:   85.0,
			AssetCoverage:  95.0,
			ThreatCoverage: 75.0,
		},
		PerformanceMetrics: PerfMetrics{
			ScanTime:     results.Duration,
			TestTime:     results.Duration,
			ResponseTime: 250 * time.Millisecond,
			Throughput:   10.0,
			ErrorRate:    2.5,
			ResourceUsage: ResourceUsage{
				CPU:     60.0,
				Memory:  45.0,
				Disk:    20.0,
				Network: 30.0,
			},
		},
	}
}

func (tf *DefaultTestingFramework) calculateSecuritySummary(results *SecurityTestResults) SecurityTestSummary {
	// Count findings by severity
	var critical, high, medium, low, info int
	for _, vuln := range results.Vulnerabilities {
		switch vuln.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		case SeverityLow:
			low++
		case SeverityInfo:
			info++
		}
	}

	// Calculate security score (higher is better)
	securityScore := 100.0 - float64(critical*20 + high*10 + medium*5 + low*2)
	if securityScore < 0 {
		securityScore = 0
	}

	// Calculate risk score (lower is better)
	riskScore := float64(critical*20 + high*10 + medium*5 + low*2)

	return SecurityTestSummary{
		TotalTests:       len(results.Vulnerabilities),
		PassedTests:      0, // Would be calculated based on test expectations
		FailedTests:      len(results.Vulnerabilities),
		CriticalFindings: critical,
		HighFindings:     high,
		MediumFindings:   medium,
		LowFindings:      low,
		InfoFindings:     info,
		SecurityScore:    securityScore,
		RiskScore:        riskScore,
		ComplianceScore:  results.Compliance.Score,
	}
}

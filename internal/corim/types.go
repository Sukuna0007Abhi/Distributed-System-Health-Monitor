package corim

import (
	"context"
	"time"

	"github.com/veraison/corim/corim"
)

// Profile represents a CoRIM profile stored in the system
type Profile struct {
	ID          string                   `json:"id" redis:"id"`
	Name        string                   `json:"name" redis:"name"`
	LoadTime    time.Time                `json:"load_time" redis:"load_time"`
	CoRIM       *corim.UnsignedCorim     `json:"corim" redis:"corim"`
	RefValues   map[string]*ReferenceValue `json:"reference_values,omitempty" redis:"ref_values"`
	Metadata    *ProfileMetadata         `json:"metadata" redis:"metadata"`
}

// ProfileMetadata contains additional information about a CoRIM profile
type ProfileMetadata struct {
	Version     string            `json:"version" redis:"version"`
	Description string            `json:"description" redis:"description"`
	Author      string            `json:"author" redis:"author"`
	Tags        map[string]string `json:"tags,omitempty" redis:"tags"`
	FilePath    string            `json:"file_path,omitempty" redis:"file_path"`
	FileSize    int64             `json:"file_size,omitempty" redis:"file_size"`
	Checksum    string            `json:"checksum,omitempty" redis:"checksum"`
}

// ReferenceValue represents an extracted reference value from CoRIM
type ReferenceValue struct {
	Key           string                 `json:"key" redis:"key"`
	Environment   *EnvironmentIdentifier `json:"environment" redis:"environment"`
	Measurements  []*Measurement         `json:"measurements" redis:"measurements"`
	TagID         string                 `json:"tag_id" redis:"tag_id"`
	ExtractedAt   time.Time              `json:"extracted_at" redis:"extracted_at"`
}

// EnvironmentIdentifier uniquely identifies the environment for reference values
type EnvironmentIdentifier struct {
	Class       string            `json:"class" redis:"class"`             // e.g., "tpm"
	Instance    string            `json:"instance,omitempty" redis:"instance"`
	Vendor      string            `json:"vendor,omitempty" redis:"vendor"`
	Model       string            `json:"model,omitempty" redis:"model"`
	Serial      string            `json:"serial,omitempty" redis:"serial"`
	Version     string            `json:"version,omitempty" redis:"version"`
	Attributes  map[string]string `json:"attributes,omitempty" redis:"attributes"`
}

// Measurement represents a single measurement with its expected value
type Measurement struct {
	Key       string            `json:"key" redis:"key"`             // e.g., "pcr-0"
	Algorithm string            `json:"algorithm" redis:"algorithm"` // e.g., "sha256"
	Digest    []byte            `json:"digest" redis:"digest"`
	Raw       []byte            `json:"raw,omitempty" redis:"raw"`
	Metadata  map[string]string `json:"metadata,omitempty" redis:"metadata"`
}

// ProfileSummary provides a lightweight view of a profile for listing operations
type ProfileSummary struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	LoadTime    time.Time          `json:"load_time"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	TagCount    int                `json:"tag_count"`
	RefCount    int                `json:"reference_value_count"`
	Metadata    *ProfileMetadata   `json:"metadata,omitempty"`
}

// ParseResult contains the result of parsing a CoRIM file
type ParseResult struct {
	Profile     *Profile          `json:"profile"`
	Warnings    []string          `json:"warnings,omitempty"`
	Statistics  *ParseStatistics  `json:"statistics,omitempty"`
}

// ParseStatistics provides metrics about the parsing operation
type ParseStatistics struct {
	TagsProcessed        int           `json:"tags_processed"`
	RefValuesExtracted   int           `json:"reference_values_extracted"`
	MeasurementsFound    int           `json:"measurements_found"`
	ParseDuration        time.Duration `json:"parse_duration"`
	ValidationDuration   time.Duration `json:"validation_duration"`
	ExtractionDuration   time.Duration `json:"extraction_duration"`
}

// ProvisioningResult contains the result of provisioning a profile
type ProvisioningResult struct {
	ProfileID      string            `json:"profile_id"`
	RefValuesStored int              `json:"reference_values_stored"`
	KeysCreated     []string         `json:"keys_created,omitempty"`
	Duration        time.Duration    `json:"duration"`
	Warnings        []string         `json:"warnings,omitempty"`
}

// QueryResult contains the result of querying reference values
type QueryResult struct {
	Values      []*ReferenceValue `json:"values"`
	Environment *EnvironmentIdentifier `json:"environment"`
	Count       int               `json:"count"`
	QueryTime   time.Duration     `json:"query_time"`
}

// ValidationResult contains detailed validation results
type ValidationResult struct {
	Valid     bool                    `json:"valid"`
	Errors    []ValidationError       `json:"errors,omitempty"`
	Warnings  []ValidationWarning     `json:"warnings,omitempty"`
	Summary   *ValidationSummary      `json:"summary"`
}

// ValidationError represents a validation error with details
type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Location    string `json:"location,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field    string `json:"field"`
	Message  string `json:"message"`
	Code     string `json:"code"`
	Location string `json:"location,omitempty"`
}

// ValidationSummary provides summary statistics for validation
type ValidationSummary struct {
	TotalChecks    int `json:"total_checks"`
	ErrorCount     int `json:"error_count"`
	WarningCount   int `json:"warning_count"`
	TagsValidated  int `json:"tags_validated"`
	MeasurementsValidated int `json:"measurements_validated"`
}

// StoreConfig contains configuration for the CoRIM store
type StoreConfig struct {
	RedisAddr       string        `yaml:"redis_addr" json:"redis_addr"`
	RedisPassword   string        `yaml:"redis_password" json:"redis_password"`
	RedisDB         int           `yaml:"redis_db" json:"redis_db"`
	KeyPrefix       string        `yaml:"key_prefix" json:"key_prefix"`
	TTL             time.Duration `yaml:"ttl" json:"ttl"`
	MaxConnections  int           `yaml:"max_connections" json:"max_connections"`
	ConnectTimeout  time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	ReadTimeout     time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout" json:"write_timeout"`
}

// ParserConfig contains configuration for the CoRIM parser
type ParserConfig struct {
	MaxFileSize      int64 `yaml:"max_file_size" json:"max_file_size"`
	ValidateOnLoad   bool  `yaml:"validate_on_load" json:"validate_on_load"`
	StrictMode       bool  `yaml:"strict_mode" json:"strict_mode"`
	EnableMetrics    bool  `yaml:"enable_metrics" json:"enable_metrics"`
	EnableDebugLogs  bool  `yaml:"enable_debug_logs" json:"enable_debug_logs"`
}

// CoRIMConfig contains the full CoRIM configuration
type CoRIMConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	ProfilesPath string        `yaml:"profiles_path" json:"profiles_path"`
	AutoLoad     bool          `yaml:"auto_load" json:"auto_load"`
	Storage      *StoreConfig  `yaml:"storage" json:"storage"`
	Parser       *ParserConfig `yaml:"parser" json:"parser"`
	Sources      []SourceConfig `yaml:"sources,omitempty" json:"sources,omitempty"`
}

// SourceConfig defines where CoRIM profiles can be loaded from
type SourceConfig struct {
	Type     string            `yaml:"type" json:"type"`         // "file", "http", "s3", etc.
	Path     string            `yaml:"path" json:"path"`         // file path or URL
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Options  map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// Constants for environment classes and algorithms
const (
	// Environment Classes
	EnvClassTPM      = "tpm"
	EnvClassTEE      = "tee" 
	EnvClassUEFI     = "uefi"
	EnvClassGeneric  = "generic"

	// Digest Algorithms
	AlgorithmSHA256   = "sha256"
	AlgorithmSHA384   = "sha384"
	AlgorithmSHA512   = "sha512"
	AlgorithmSHA1     = "sha1"

	// Algorithm digest lengths
	SHA256Length = 32
	SHA384Length = 48
	SHA512Length = 64
	SHA1Length   = 20

	// Redis key patterns
	ProfileKeyPrefix    = "corim:profiles"
	RefValueKeyPrefix   = "corim:refvalues"
	IndexKey           = "corim:index"
	MetricsKeyPrefix   = "corim:metrics"

	// Validation error codes
	ErrCodeMissingID           = "MISSING_ID"
	ErrCodeInvalidDigestLength = "INVALID_DIGEST_LENGTH"
	ErrCodeUnsupportedAlgorithm = "UNSUPPORTED_ALGORITHM"
	ErrCodeMissingEnvironment  = "MISSING_ENVIRONMENT"
	ErrCodeInvalidCBOR        = "INVALID_CBOR"
	ErrCodeEmptyProfile       = "EMPTY_PROFILE"
)

// Interfaces for dependency injection and testing

// StoreInterface defines the interface for CoRIM storage operations
type StoreInterface interface {
	StoreProfile(ctx context.Context, profile *Profile) error
	GetProfile(ctx context.Context, profileID string) (*Profile, error)
	StoreReferenceValue(ctx context.Context, refValue *ReferenceValue) error
	GetReferenceValue(ctx context.Context, key string) (*ReferenceValue, error)
	GetReferenceValuesByEnvironment(ctx context.Context, env *EnvironmentIdentifier) ([]*ReferenceValue, error)
	ListProfiles(ctx context.Context) ([]string, error)
	GetProfileSummaries(ctx context.Context) ([]*ProfileSummary, error)
	DeleteProfile(ctx context.Context, profileID string) error
	Exists(ctx context.Context, profileID string) (bool, error)
	GetStats(ctx context.Context) (map[string]interface{}, error)
	Close() error
}

// ParserInterface defines the interface for CoRIM parsing operations  
type ParserInterface interface {
	Parse(ctx context.Context, corimData []byte) (*ParseResult, error)
	ParseFile(ctx context.Context, filename string) (*ParseResult, error)
	Validate(profile *Profile) (*ValidationResult, error)
}
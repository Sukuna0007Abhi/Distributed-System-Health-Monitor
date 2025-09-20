package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Redis       RedisConfig       `mapstructure:"redis"`
	NATS        NATSConfig        `mapstructure:"nats"`
	Kafka       KafkaConfig       `mapstructure:"kafka"`
	Attestation AttestationConfig `mapstructure:"attestation"`
	Security    SecurityConfig    `mapstructure:"security"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Metrics     MetricsConfig     `mapstructure:"metrics"`
	Tracing     TracingConfig     `mapstructure:"tracing"`
	ML          MLConfig          `mapstructure:"ml"`
	Consensus   ConsensusConfig   `mapstructure:"consensus"`
	MultiCloud  MultiCloudConfig  `mapstructure:"multicloud"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	TLS          TLSConfig     `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
}

type DatabaseConfig struct {
	Driver          string        `mapstructure:"driver"`
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
	Address     string        `mapstructure:"address"`
	Password    string        `mapstructure:"password"`
	DB          int           `mapstructure:"db"`
	PoolSize    int           `mapstructure:"pool_size"`
	MaxRetries  int           `mapstructure:"max_retries"`
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
	Cluster     ClusterConfig `mapstructure:"cluster"`
}

type ClusterConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Addresses []string `mapstructure:"addresses"`
}

type NATSConfig struct {
	URL            string        `mapstructure:"url"`
	MaxReconnects  int           `mapstructure:"max_reconnects"`
	ReconnectWait  time.Duration `mapstructure:"reconnect_wait"`
	Timeout        time.Duration `mapstructure:"timeout"`
	JetStream      bool          `mapstructure:"jetstream"`
	ClusterID      string        `mapstructure:"cluster_id"`
	ClientID       string        `mapstructure:"client_id"`
	DurableName    string        `mapstructure:"durable_name"`
	StreamName     string        `mapstructure:"stream_name"`
	Subjects       []string      `mapstructure:"subjects"`
}

type KafkaConfig struct {
	Brokers       []string      `mapstructure:"brokers"`
	GroupID       string        `mapstructure:"group_id"`
	Topic         string        `mapstructure:"topic"`
	BatchSize     int           `mapstructure:"batch_size"`
	BatchTimeout  time.Duration `mapstructure:"batch_timeout"`
	RetryMax      int           `mapstructure:"retry_max"`
	RetryInterval time.Duration `mapstructure:"retry_interval"`
	SASL          SASLConfig    `mapstructure:"sasl"`
	TLS           TLSConfig     `mapstructure:"tls"`
}

type SASLConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Username  string `mapstructure:"username"`
	Password  string `mapstructure:"password"`
	Mechanism string `mapstructure:"mechanism"`
}

type AttestationConfig struct {
	EnableRATSCompliance bool                  `mapstructure:"enable_rats_compliance"`
	VerificationTimeout  time.Duration         `mapstructure:"verification_timeout"`
	MaxConcurrentVerify  int                   `mapstructure:"max_concurrent_verify"`
	CacheEnabled         bool                  `mapstructure:"cache_enabled"`
	CacheTTL             time.Duration         `mapstructure:"cache_ttl"`
	PolicyEngine         PolicyEngineConfig    `mapstructure:"policy_engine"`
	Hardware             HardwareConfig        `mapstructure:"hardware"`
	Evidence             EvidenceConfig        `mapstructure:"evidence"`
	QoS                  QoSConfig             `mapstructure:"qos"`
}

type PolicyEngineConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	OPAAddress    string   `mapstructure:"opa_address"`
	PolicyPath    string   `mapstructure:"policy_path"`
	DefaultPolicy string   `mapstructure:"default_policy"`
	RegoPackages  []string `mapstructure:"rego_packages"`
}

type HardwareConfig struct {
	TPMEnabled       bool   `mapstructure:"tpm_enabled"`
	TPMDevice        string `mapstructure:"tpm_device"`
	IntelTXTEnabled  bool   `mapstructure:"intel_txt_enabled"`
	AMDSVMEnabled    bool   `mapstructure:"amd_svm_enabled"`
	SecureBootCheck  bool   `mapstructure:"secure_boot_check"`
	IMREnabled       bool   `mapstructure:"imr_enabled"`
}

type EvidenceConfig struct {
	MaxSize        int           `mapstructure:"max_size"`
	Compression    bool          `mapstructure:"compression"`
	Encryption     bool          `mapstructure:"encryption"`
	SigningEnabled bool          `mapstructure:"signing_enabled"`
	SigningKeyPath string        `mapstructure:"signing_key_path"`
	RetentionDays  int           `mapstructure:"retention_days"`
	StoragePath    string        `mapstructure:"storage_path"`
}

type QoSConfig struct {
	HighPriorityLatencyTarget time.Duration `mapstructure:"high_priority_latency_target"`
	MediumPriorityLatencyTarget time.Duration `mapstructure:"medium_priority_latency_target"`
	LowPriorityLatencyTarget time.Duration `mapstructure:"low_priority_latency_target"`
	BatchProcessingEnabled   bool          `mapstructure:"batch_processing_enabled"`
	BatchSize                int           `mapstructure:"batch_size"`
	BatchTimeout             time.Duration `mapstructure:"batch_timeout"`
}

type SecurityConfig struct {
	SPIFFEEnabled     bool          `mapstructure:"spiffe_enabled"`
	SPIFFESocketPath  string        `mapstructure:"spiffe_socket_path"`
	SPIRETrustDomain  string        `mapstructure:"spire_trust_domain"`
	JWTSigningKey     string        `mapstructure:"jwt_signing_key"`
	JWTExpiryDuration time.Duration `mapstructure:"jwt_expiry_duration"`
	RBAC              RBACConfig    `mapstructure:"rbac"`
	Encryption        EncryptionConfig `mapstructure:"encryption"`
}

type RBACConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	PolicyPath  string            `mapstructure:"policy_path"`
	Roles       map[string][]string `mapstructure:"roles"`
	DefaultRole string            `mapstructure:"default_role"`
}

type EncryptionConfig struct {
	Algorithm      string `mapstructure:"algorithm"`
	KeySize        int    `mapstructure:"key_size"`
	KeyRotationDays int   `mapstructure:"key_rotation_days"`
	KeyStorePath   string `mapstructure:"key_store_path"`
}

type LoggingConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Output      string `mapstructure:"output"`
	FileRotation bool  `mapstructure:"file_rotation"`
	MaxSize     int    `mapstructure:"max_size"`
	MaxBackups  int    `mapstructure:"max_backups"`
	MaxAge      int    `mapstructure:"max_age"`
}

type MetricsConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	Address    string        `mapstructure:"address"`
	Path       string        `mapstructure:"path"`
	Interval   time.Duration `mapstructure:"interval"`
	Namespace  string        `mapstructure:"namespace"`
	Subsystem  string        `mapstructure:"subsystem"`
	SLI        SLIConfig     `mapstructure:"sli"`
}

type SLIConfig struct {
	AttestationLatencyTarget time.Duration `mapstructure:"attestation_latency_target"`
	AttestationSuccessRate   float64       `mapstructure:"attestation_success_rate"`
	AvailabilityTarget       float64       `mapstructure:"availability_target"`
	ThroughputTarget         int64         `mapstructure:"throughput_target"`
}

type TracingConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	ServiceName  string        `mapstructure:"service_name"`
	Endpoint     string        `mapstructure:"endpoint"`
	SampleRate   float64       `mapstructure:"sample_rate"`
	BatchTimeout time.Duration `mapstructure:"batch_timeout"`
}

type MLConfig struct {
	Enabled             bool          `mapstructure:"enabled"`
	ModelPath           string        `mapstructure:"model_path"`
	AnomalyThreshold    float64       `mapstructure:"anomaly_threshold"`
	TrainingInterval    time.Duration `mapstructure:"training_interval"`
	PredictionInterval  time.Duration `mapstructure:"prediction_interval"`
	FeatureWindow       time.Duration `mapstructure:"feature_window"`
	TensorFlowLiteModel string        `mapstructure:"tensorflow_lite_model"`
	GPUEnabled          bool          `mapstructure:"gpu_enabled"`
}

type ConsensusConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	NodeID            string        `mapstructure:"node_id"`
	DataDir           string        `mapstructure:"data_dir"`
	BindAddress       string        `mapstructure:"bind_address"`
	Bootstrap         bool          `mapstructure:"bootstrap"`
	BootstrapPeers    []string      `mapstructure:"bootstrap_peers"`
	HeartbeatTimeout  time.Duration `mapstructure:"heartbeat_timeout"`
	ElectionTimeout   time.Duration `mapstructure:"election_timeout"`
	CommitTimeout     time.Duration `mapstructure:"commit_timeout"`
	MaxAppendEntries  int           `mapstructure:"max_append_entries"`
	SnapshotInterval  time.Duration `mapstructure:"snapshot_interval"`
	SnapshotThreshold uint64        `mapstructure:"snapshot_threshold"`
}

type MultiCloudConfig struct {
	AWS   AWSConfig   `mapstructure:"aws"`
	Azure AzureConfig `mapstructure:"azure"`
	GCP   GCPConfig   `mapstructure:"gcp"`
}

type AWSConfig struct {
	Enabled          bool              `mapstructure:"enabled"`
	Region           string            `mapstructure:"region"`
	AccessKeyID      string            `mapstructure:"access_key_id"`
	SecretAccessKey  string            `mapstructure:"secret_access_key"`
	NitroEnclaves    NitroEnclavesConfig `mapstructure:"nitro_enclaves"`
}

type NitroEnclavesConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	PCRs          []int  `mapstructure:"pcrs"`
	AttestationDoc string `mapstructure:"attestation_doc"`
}

type AzureConfig struct {
	Enabled              bool                           `mapstructure:"enabled"`
	TenantID             string                         `mapstructure:"tenant_id"`
	ClientID             string                         `mapstructure:"client_id"`
	ClientSecret         string                         `mapstructure:"client_secret"`
	ConfidentialComputing ConfidentialComputingConfig    `mapstructure:"confidential_computing"`
}

type ConfidentialComputingConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	AttestationProvider string `mapstructure:"attestation_provider"`
	PolicyVersion string `mapstructure:"policy_version"`
}

type GCPConfig struct {
	Enabled         bool                  `mapstructure:"enabled"`
	ProjectID       string                `mapstructure:"project_id"`
	CredentialsPath string                `mapstructure:"credentials_path"`
	ShieldedVMs     ShieldedVMsConfig     `mapstructure:"shielded_vms"`
}

type ShieldedVMsConfig struct {
	Enabled                bool `mapstructure:"enabled"`
	SecureBootEnabled      bool `mapstructure:"secure_boot_enabled"`
	VtpmEnabled            bool `mapstructure:"vtpm_enabled"`
	IntegrityMonitoring    bool `mapstructure:"integrity_monitoring"`
}

// Load loads configuration from file
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set defaults
	setDefaults()

	// Enable environment variable support
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Attestation.VerificationTimeout <= 0 {
		return fmt.Errorf("verification timeout must be positive")
	}

	if c.Attestation.MaxConcurrentVerify <= 0 {
		return fmt.Errorf("max concurrent verifications must be positive")
	}

	if c.ML.Enabled && c.ML.AnomalyThreshold <= 0 {
		return fmt.Errorf("anomaly threshold must be positive when ML is enabled")
	}

	if c.Consensus.Enabled && c.Consensus.NodeID == "" {
		return fmt.Errorf("node ID is required when consensus is enabled")
	}

	return nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")

	// Attestation defaults
	viper.SetDefault("attestation.enable_rats_compliance", true)
	viper.SetDefault("attestation.verification_timeout", "10s")
	viper.SetDefault("attestation.max_concurrent_verify", 100)
	viper.SetDefault("attestation.cache_enabled", true)
	viper.SetDefault("attestation.cache_ttl", "5m")

	// QoS defaults
	viper.SetDefault("attestation.qos.high_priority_latency_target", "5ms")
	viper.SetDefault("attestation.qos.medium_priority_latency_target", "10ms")
	viper.SetDefault("attestation.qos.low_priority_latency_target", "50ms")
	viper.SetDefault("attestation.qos.batch_processing_enabled", true)
	viper.SetDefault("attestation.qos.batch_size", 100)
	viper.SetDefault("attestation.qos.batch_timeout", "100ms")

	// Hardware defaults
	viper.SetDefault("attestation.hardware.tpm_enabled", true)
	viper.SetDefault("attestation.hardware.tpm_device", "/dev/tpm0")
	viper.SetDefault("attestation.hardware.secure_boot_check", true)

	// ML defaults
	viper.SetDefault("ml.enabled", true)
	viper.SetDefault("ml.anomaly_threshold", 0.8)
	viper.SetDefault("ml.training_interval", "1h")
	viper.SetDefault("ml.prediction_interval", "1m")
	viper.SetDefault("ml.feature_window", "10m")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.address", ":9090")
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.interval", "15s")
	viper.SetDefault("metrics.namespace", "health_monitor")

	// SLI defaults
	viper.SetDefault("metrics.sli.attestation_latency_target", "10ms")
	viper.SetDefault("metrics.sli.attestation_success_rate", 0.995)
	viper.SetDefault("metrics.sli.availability_target", 0.999)
	viper.SetDefault("metrics.sli.throughput_target", 10000)

	// Tracing defaults
	viper.SetDefault("tracing.enabled", true)
	viper.SetDefault("tracing.service_name", "health-monitor")
	viper.SetDefault("tracing.sample_rate", 0.1)
	viper.SetDefault("tracing.batch_timeout", "5s")

	// Redis defaults
	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.max_retries", 3)
	viper.SetDefault("redis.read_timeout", "3s")

	// NATS defaults
	viper.SetDefault("nats.url", "nats://localhost:4222")
	viper.SetDefault("nats.max_reconnects", 10)
	viper.SetDefault("nats.reconnect_wait", "2s")
	viper.SetDefault("nats.timeout", "2s")
	viper.SetDefault("nats.jetstream", true)

	// Consensus defaults
	viper.SetDefault("consensus.heartbeat_timeout", "1s")
	viper.SetDefault("consensus.election_timeout", "1s")
	viper.SetDefault("consensus.commit_timeout", "50ms")
	viper.SetDefault("consensus.max_append_entries", 64)
	viper.SetDefault("consensus.snapshot_interval", "120s")
	viper.SetDefault("consensus.snapshot_threshold", 8192)
}

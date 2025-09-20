package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/attestation"
	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/sirupsen/logrus"
)

// PolicyEngine interface for policy evaluation
type PolicyEngine interface {
	// GetPolicy retrieves a policy by ID
	GetPolicy(ctx context.Context, policyID string) (*attestation.Policy, error)
	
	// EvaluatePolicy evaluates a policy against evidence and verification results
	EvaluatePolicy(ctx context.Context, policyID string, evidence []*attestation.Evidence, results []*attestation.VerificationResult) (*attestation.PolicyEvaluationResult, error)
	
	// LoadPolicies loads policies from the configured source
	LoadPolicies(ctx context.Context) error
	
	// RegisterPlugin registers a policy plugin
	RegisterPlugin(plugin PolicyPlugin) error
	
	// UnregisterPlugin unregisters a policy plugin
	UnregisterPlugin(pluginName string) error
	
	// ListPlugins lists all registered plugins
	ListPlugins() []string
	
	// Close closes the policy engine
	Close() error
}

// PolicyPlugin interface for policy plugins
type PolicyPlugin interface {
	// Name returns the plugin name
	Name() string
	
	// Version returns the plugin version
	Version() string
	
	// Initialize initializes the plugin
	Initialize(config map[string]interface{}) error
	
	// EvaluatePolicy evaluates a policy using the plugin
	EvaluatePolicy(ctx context.Context, input PolicyInput) (*PolicyOutput, error)
	
	// GetCapabilities returns the plugin capabilities
	GetCapabilities() PolicyPluginCapabilities
	
	// Close closes the plugin
	Close() error
}

// PolicyInput represents input for policy evaluation
type PolicyInput struct {
	TenantID    string                           `json:"tenant_id"`
	RequestID   string                           `json:"request_id"`
	Evidence    []*attestation.Evidence          `json:"evidence"`
	Results     []*attestation.VerificationResult `json:"results"`
	Context     map[string]interface{}           `json:"context"`
	Timestamp   time.Time                        `json:"timestamp"`
}

// PolicyOutput represents output from policy evaluation
type PolicyOutput struct {
	Decision    attestation.PolicyDecision    `json:"decision"`
	Violations  []attestation.PolicyViolation `json:"violations"`
	Warnings    []attestation.PolicyWarning   `json:"warnings"`
	Score       float64                       `json:"score"`
	Metadata    map[string]interface{}        `json:"metadata"`
	EvaluatedAt time.Time                     `json:"evaluated_at"`
}

// PolicyPluginCapabilities defines plugin capabilities
type PolicyPluginCapabilities struct {
	SupportedLanguages []string               `json:"supported_languages"`
	SupportedFormats   []string               `json:"supported_formats"`
	MaxPolicySize      int64                  `json:"max_policy_size"`
	ConcurrentEvals    int                    `json:"concurrent_evaluations"`
	Features           []string               `json:"features"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// OPAPolicyEngine implements PolicyEngine using Open Policy Agent
type OPAPolicyEngine struct {
	config       config.PolicyEngineConfig
	logger       *logrus.Logger
	store        storage.Store
	compiler     *ast.Compiler
	policies     map[string]*attestation.Policy
	policiesMux  sync.RWMutex
	plugins      map[string]PolicyPlugin
	pluginsMux   sync.RWMutex
	bundleReader *bundle.Reader
	running      bool
	stopCh       chan struct{}
}

// NewOPAPolicyEngine creates a new OPA-based policy engine
func NewOPAPolicyEngine(cfg config.PolicyEngineConfig, logger *logrus.Logger) (*OPAPolicyEngine, error) {
	// Create in-memory store
	store := inmem.New()
	
	engine := &OPAPolicyEngine{
		config:   cfg,
		logger:   logger,
		store:    store,
		policies: make(map[string]*attestation.Policy),
		plugins:  make(map[string]PolicyPlugin),
		stopCh:   make(chan struct{}),
	}
	
	// Initialize compiler
	if err := engine.initializeCompiler(); err != nil {
		return nil, fmt.Errorf("failed to initialize compiler: %w", err)
	}
	
	// Load default policies
	if err := engine.LoadPolicies(context.Background()); err != nil {
		logger.WithError(err).Warn("Failed to load initial policies")
	}
	
	// Register default plugins
	if err := engine.registerDefaultPlugins(); err != nil {
		return nil, fmt.Errorf("failed to register default plugins: %w", err)
	}
	
	engine.running = true
	return engine, nil
}

// initializeCompiler initializes the OPA compiler
func (e *OPAPolicyEngine) initializeCompiler() error {
	// Create new compiler
	e.compiler = ast.NewCompiler()
	
	// Add built-in functions if needed
	// This is where you can extend OPA with custom functions
	
	return nil
}

// GetPolicy retrieves a policy by ID
func (e *OPAPolicyEngine) GetPolicy(ctx context.Context, policyID string) (*attestation.Policy, error) {
	e.policiesMux.RLock()
	defer e.policiesMux.RUnlock()
	
	policy, exists := e.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}
	
	return policy, nil
}

// EvaluatePolicy evaluates a policy against evidence and verification results
func (e *OPAPolicyEngine) EvaluatePolicy(ctx context.Context, policyID string, evidence []*attestation.Evidence, results []*attestation.VerificationResult) (*attestation.PolicyEvaluationResult, error) {
	// Get policy
	policy, err := e.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	
	// Prepare input for evaluation
	input := PolicyInput{
		Evidence:    evidence,
		Results:     results,
		Context:     make(map[string]interface{}),
		Timestamp:   time.Now(),
	}
	
	// Try plugin-based evaluation first
	if pluginResult := e.tryPluginEvaluation(ctx, policy, input); pluginResult != nil {
		return e.convertPluginOutput(policy, pluginResult), nil
	}
	
	// Fall back to OPA evaluation
	return e.evaluateWithOPA(ctx, policy, input)
}

// tryPluginEvaluation tries to evaluate using registered plugins
func (e *OPAPolicyEngine) tryPluginEvaluation(ctx context.Context, policy *attestation.Policy, input PolicyInput) *PolicyOutput {
	e.pluginsMux.RLock()
	defer e.pluginsMux.RUnlock()
	
	// Check if policy specifies a plugin
	if pluginName, ok := policy.Metadata["plugin"]; ok {
		if plugin, exists := e.plugins[pluginName.(string)]; exists {
			if output, err := plugin.EvaluatePolicy(ctx, input); err == nil {
				return output
			} else {
				e.logger.WithError(err).WithField("plugin", pluginName).Warn("Plugin evaluation failed")
			}
		}
	}
	
	// Try each plugin until one succeeds
	for name, plugin := range e.plugins {
		if output, err := plugin.EvaluatePolicy(ctx, input); err == nil {
			e.logger.WithField("plugin", name).Debug("Plugin evaluation successful")
			return output
		}
	}
	
	return nil
}

// evaluateWithOPA evaluates using OPA Rego
func (e *OPAPolicyEngine) evaluateWithOPA(ctx context.Context, policy *attestation.Policy, input PolicyInput) (*attestation.PolicyEvaluationResult, error) {
	// Convert policy rules to Rego
	regoCode, err := e.convertPolicyToRego(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy to Rego: %w", err)
	}
	
	// Create Rego query
	query := rego.New(
		rego.Query("data.attestation.decision"),
		rego.Module("attestation.rego", regoCode),
		rego.Input(input),
		rego.Store(e.store),
		rego.Compiler(e.compiler),
	)
	
	// Prepare query
	prepared, err := query.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}
	
	// Evaluate query
	results, err := prepared.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	
	if len(results) == 0 {
		return &attestation.PolicyEvaluationResult{
			PolicyID:    policy.ID,
			Version:     policy.Version,
			Decision:    attestation.DecisionDeny,
			Score:       0.0,
			EvaluatedAt: time.Now(),
		}, nil
	}
	
	// Parse results
	return e.parseOPAResults(policy, results[0])
}

// convertPolicyToRego converts a policy to Rego code
func (e *OPAPolicyEngine) convertPolicyToRego(policy *attestation.Policy) (string, error) {
	var regoBuilder strings.Builder
	
	regoBuilder.WriteString("package attestation\n\n")
	regoBuilder.WriteString("default decision = \"deny\"\n")
	regoBuilder.WriteString("default score = 0.0\n")
	regoBuilder.WriteString("violations = []\n")
	regoBuilder.WriteString("warnings = []\n\n")
	
	// Convert each rule
	for _, rule := range policy.Rules {
		regoRule, err := e.convertRuleToRego(rule)
		if err != nil {
			return "", fmt.Errorf("failed to convert rule %s: %w", rule.ID, err)
		}
		regoBuilder.WriteString(regoRule)
		regoBuilder.WriteString("\n\n")
	}
	
	// Add decision logic
	regoBuilder.WriteString(`
decision = "allow" {
	count(violations) == 0
	score >= 0.7
}

decision = "warn" {
	count(violations) == 0
	score < 0.7
	score >= 0.5
}

decision = "deny" {
	count(violations) > 0
}

decision = "deny" {
	score < 0.5
}

score = s {
	evidence_scores := [score | 
		input.evidence[_].claims.trust_level = score
	]
	s := (sum(evidence_scores) / count(evidence_scores))
}
`)
	
	return regoBuilder.String(), nil
}

// convertRuleToRego converts a single rule to Rego
func (e *OPAPolicyEngine) convertRuleToRego(rule attestation.PolicyRule) (string, error) {
	var regoBuilder strings.Builder
	
	switch rule.Action {
	case attestation.ActionRequire:
		regoBuilder.WriteString(fmt.Sprintf(`
violations[violation] {
	not (%s)
	violation := {
		"rule": "%s",
		"severity": "%s",
		"message": "%s"
	}
}`, rule.Condition, rule.ID, rule.Severity, rule.Description))
		
	case attestation.ActionDeny:
		regoBuilder.WriteString(fmt.Sprintf(`
violations[violation] {
	%s
	violation := {
		"rule": "%s",
		"severity": "%s",
		"message": "%s"
	}
}`, rule.Condition, rule.ID, rule.Severity, rule.Description))
		
	case attestation.ActionWarn:
		regoBuilder.WriteString(fmt.Sprintf(`
warnings[warning] {
	%s
	warning := {
		"rule": "%s",
		"message": "%s"
	}
}`, rule.Condition, rule.ID, rule.Description))
	}
	
	return regoBuilder.String(), nil
}

// parseOPAResults parses OPA evaluation results
func (e *OPAPolicyEngine) parseOPAResults(policy *attestation.Policy, result rego.Result) (*attestation.PolicyEvaluationResult, error) {
	evalResult := &attestation.PolicyEvaluationResult{
		PolicyID:    policy.ID,
		Version:     policy.Version,
		EvaluatedAt: time.Now(),
		Context:     make(map[string]interface{}),
	}
	
	// Extract decision
	if decision, ok := result.Bindings["decision"].(string); ok {
		evalResult.Decision = attestation.PolicyDecision(decision)
	} else {
		evalResult.Decision = attestation.DecisionDeny
	}
	
	// Extract score
	if score, ok := result.Bindings["score"].(float64); ok {
		evalResult.Score = score
	}
	
	// Extract violations
	if violations, ok := result.Bindings["violations"].([]interface{}); ok {
		for _, v := range violations {
			if violation, ok := v.(map[string]interface{}); ok {
				policyViolation := attestation.PolicyViolation{
					Rule:     violation["rule"].(string),
					Severity: violation["severity"].(string),
					Message:  violation["message"].(string),
					Context:  make(map[string]interface{}),
				}
				evalResult.Violations = append(evalResult.Violations, policyViolation)
			}
		}
	}
	
	// Extract warnings
	if warnings, ok := result.Bindings["warnings"].([]interface{}); ok {
		for _, w := range warnings {
			if warning, ok := w.(map[string]interface{}); ok {
				policyWarning := attestation.PolicyWarning{
					Rule:    warning["rule"].(string),
					Message: warning["message"].(string),
					Context: make(map[string]interface{}),
				}
				evalResult.Warnings = append(evalResult.Warnings, policyWarning)
			}
		}
	}
	
	return evalResult, nil
}

// convertPluginOutput converts plugin output to policy evaluation result
func (e *OPAPolicyEngine) convertPluginOutput(policy *attestation.Policy, output *PolicyOutput) *attestation.PolicyEvaluationResult {
	return &attestation.PolicyEvaluationResult{
		PolicyID:    policy.ID,
		Version:     policy.Version,
		Decision:    output.Decision,
		Violations:  output.Violations,
		Warnings:    output.Warnings,
		Score:       output.Score,
		EvaluatedAt: output.EvaluatedAt,
		Context:     output.Metadata,
	}
}

// LoadPolicies loads policies from the configured source
func (e *OPAPolicyEngine) LoadPolicies(ctx context.Context) error {
	if e.config.PolicyPath == "" {
		return nil // No policies to load
	}
	
	// Check if path is a file or directory
	info, err := os.Stat(e.config.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to stat policy path: %w", err)
	}
	
	if info.IsDir() {
		return e.loadPoliciesFromDirectory(ctx, e.config.PolicyPath)
	} else {
		return e.loadPolicyFromFile(ctx, e.config.PolicyPath)
	}
}

// loadPoliciesFromDirectory loads all policies from a directory
func (e *OPAPolicyEngine) loadPoliciesFromDirectory(ctx context.Context, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && (strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			if err := e.loadPolicyFromFile(ctx, path); err != nil {
				e.logger.WithError(err).WithField("file", path).Warn("Failed to load policy file")
			}
		}
		
		return nil
	})
}

// loadPolicyFromFile loads a single policy from a file
func (e *OPAPolicyEngine) loadPolicyFromFile(ctx context.Context, filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}
	
	var policy attestation.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	
	// Validate policy
	if err := e.validatePolicy(&policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}
	
	// Store policy
	e.policiesMux.Lock()
	e.policies[policy.ID] = &policy
	e.policiesMux.Unlock()
	
	e.logger.WithFields(logrus.Fields{
		"policy_id": policy.ID,
		"version":   policy.Version,
		"file":      filePath,
	}).Info("Loaded policy")
	
	return nil
}

// validatePolicy validates a policy
func (e *OPAPolicyEngine) validatePolicy(policy *attestation.Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if policy.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	
	for _, rule := range policy.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule ID is required")
		}
		if rule.Condition == "" {
			return fmt.Errorf("rule condition is required")
		}
	}
	
	return nil
}

// RegisterPlugin registers a policy plugin
func (e *OPAPolicyEngine) RegisterPlugin(plugin PolicyPlugin) error {
	e.pluginsMux.Lock()
	defer e.pluginsMux.Unlock()
	
	name := plugin.Name()
	if _, exists := e.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}
	
	e.plugins[name] = plugin
	e.logger.WithFields(logrus.Fields{
		"plugin": name,
		"version": plugin.Version(),
	}).Info("Registered policy plugin")
	
	return nil
}

// UnregisterPlugin unregisters a policy plugin
func (e *OPAPolicyEngine) UnregisterPlugin(pluginName string) error {
	e.pluginsMux.Lock()
	defer e.pluginsMux.Unlock()
	
	plugin, exists := e.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	// Close the plugin
	if err := plugin.Close(); err != nil {
		e.logger.WithError(err).WithField("plugin", pluginName).Warn("Failed to close plugin")
	}
	
	delete(e.plugins, pluginName)
	e.logger.WithField("plugin", pluginName).Info("Unregistered policy plugin")
	
	return nil
}

// ListPlugins lists all registered plugins
func (e *OPAPolicyEngine) ListPlugins() []string {
	e.pluginsMux.RLock()
	defer e.pluginsMux.RUnlock()
	
	plugins := make([]string, 0, len(e.plugins))
	for name := range e.plugins {
		plugins = append(plugins, name)
	}
	
	return plugins
}

// registerDefaultPlugins registers default policy plugins
func (e *OPAPolicyEngine) registerDefaultPlugins() error {
	// Register NIST 800-155 plugin
	nistPlugin := NewNIST800155Plugin(e.logger)
	if err := e.RegisterPlugin(nistPlugin); err != nil {
		return fmt.Errorf("failed to register NIST plugin: %w", err)
	}
	
	// Register SLSA plugin
	slsaPlugin := NewSLSAPlugin(e.logger)
	if err := e.RegisterPlugin(slsaPlugin); err != nil {
		return fmt.Errorf("failed to register SLSA plugin: %w", err)
	}
	
	// Register compliance plugin
	compliancePlugin := NewCompliancePlugin(e.logger)
	if err := e.RegisterPlugin(compliancePlugin); err != nil {
		return fmt.Errorf("failed to register compliance plugin: %w", err)
	}
	
	return nil
}

// Close closes the policy engine
func (e *OPAPolicyEngine) Close() error {
	if !e.running {
		return nil
	}
	
	e.running = false
	close(e.stopCh)
	
	// Close all plugins
	e.pluginsMux.Lock()
	for name, plugin := range e.plugins {
		if err := plugin.Close(); err != nil {
			e.logger.WithError(err).WithField("plugin", name).Warn("Failed to close plugin")
		}
	}
	e.pluginsMux.Unlock()
	
	return nil
}

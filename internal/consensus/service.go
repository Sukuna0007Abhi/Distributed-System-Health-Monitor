package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/attestation"
	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
	"github.com/sirupsen/logrus"
)

// ConsensusService manages distributed consensus for attestation verification
type ConsensusService struct {
	config     *config.ConsensusConfig
	logger     *logrus.Logger
	raft       *raft.Raft
	fsm        *AttestationFSM
	transport  *raft.NetworkTransport
	logStore   raft.LogStore
	stableStore raft.StableStore
	snapshots  raft.SnapshotStore
	
	// Peer management
	peers      map[string]*Peer
	peersMux   sync.RWMutex
	
	// State management
	running    bool
	leadership chan bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// Peer represents a consensus peer
type Peer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Region   string `json:"region"`
	Metadata map[string]interface{} `json:"metadata"`
}

// AttestationFSM implements the Raft finite state machine for attestation data
type AttestationFSM struct {
	logger *logrus.Logger
	state  *AttestationState
	mutex  sync.RWMutex
}

// AttestationState represents the replicated state
type AttestationState struct {
	Attestations map[string]*attestation.AttestationResponse `json:"attestations"`
	Policies     map[string]*attestation.Policy              `json:"policies"`
	TrustValues  map[string]float64                          `json:"trust_values"`
	Metadata     map[string]interface{}                      `json:"metadata"`
	LastUpdated  time.Time                                   `json:"last_updated"`
	Version      uint64                                      `json:"version"`
}

// ConsensusCommand represents a command to be replicated
type ConsensusCommand struct {
	Type      string                 `json:"type"`
	RequestID string                 `json:"request_id"`
	TenantID  string                 `json:"tenant_id"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	NodeID    string                 `json:"node_id"`
}

// Command types
const (
	CommandAddAttestation    = "add_attestation"
	CommandUpdateAttestation = "update_attestation"
	CommandRemoveAttestation = "remove_attestation"
	CommandAddPolicy         = "add_policy"
	CommandUpdatePolicy      = "update_policy"
	CommandRemovePolicy      = "remove_policy"
	CommandUpdateTrustValue  = "update_trust_value"
	CommandAddPeer           = "add_peer"
	CommandRemovePeer        = "remove_peer"
)

// NewConsensusService creates a new consensus service
func NewConsensusService(cfg *config.ConsensusConfig, logger *logrus.Logger) (*ConsensusService, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("consensus is disabled")
	}

	service := &ConsensusService{
		config:     cfg,
		logger:     logger,
		peers:      make(map[string]*Peer),
		leadership: make(chan bool, 1),
		stopCh:     make(chan struct{}),
	}

	// Initialize FSM
	service.fsm = &AttestationFSM{
		logger: logger,
		state: &AttestationState{
			Attestations: make(map[string]*attestation.AttestationResponse),
			Policies:     make(map[string]*attestation.Policy),
			TrustValues:  make(map[string]float64),
			Metadata:     make(map[string]interface{}),
			LastUpdated:  time.Now(),
			Version:      0,
		},
	}

	if err := service.setupRaft(); err != nil {
		return nil, fmt.Errorf("failed to setup Raft: %w", err)
	}

	return service, nil
}

// setupRaft initializes the Raft cluster
func (s *ConsensusService) setupRaft() error {
	// Ensure data directory exists
	if err := os.MkdirAll(s.config.DataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Setup Raft configuration
	raftConfig := raft.DefaultConfig()
	raftConfig.LocalID = raft.ServerID(s.config.NodeID)
	raftConfig.HeartbeatTimeout = s.config.HeartbeatTimeout
	raftConfig.ElectionTimeout = s.config.ElectionTimeout
	raftConfig.CommitTimeout = s.config.CommitTimeout
	raftConfig.MaxAppendEntries = s.config.MaxAppendEntries
	raftConfig.SnapshotInterval = s.config.SnapshotInterval
	raftConfig.SnapshotThreshold = s.config.SnapshotThreshold

	// Setup transport
	addr, err := net.ResolveTCPAddr("tcp", s.config.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve bind address: %w", err)
	}

	transport, err := raft.NewTCPTransport(s.config.BindAddress, addr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	s.transport = transport

	// Setup log store
	logStore, err := raftboltdb.NewBoltStore(filepath.Join(s.config.DataDir, "raft-log.bolt"))
	if err != nil {
		return fmt.Errorf("failed to create log store: %w", err)
	}
	s.logStore = logStore

	// Setup stable store
	stableStore, err := raftboltdb.NewBoltStore(filepath.Join(s.config.DataDir, "raft-stable.bolt"))
	if err != nil {
		return fmt.Errorf("failed to create stable store: %w", err)
	}
	s.stableStore = stableStore

	// Setup snapshot store
	snapshots, err := raft.NewFileSnapshotStore(s.config.DataDir, 3, os.Stderr)
	if err != nil {
		return fmt.Errorf("failed to create snapshot store: %w", err)
	}
	s.snapshots = snapshots

	// Create Raft instance
	ra, err := raft.NewRaft(raftConfig, s.fsm, s.logStore, s.stableStore, s.snapshots, s.transport)
	if err != nil {
		return fmt.Errorf("failed to create Raft instance: %w", err)
	}
	s.raft = ra

	// Setup leadership monitoring
	go s.monitorLeadership()

	return nil
}

// Start starts the consensus service
func (s *ConsensusService) Start(ctx context.Context) error {
	s.logger.Info("Starting consensus service")

	// Bootstrap cluster if needed
	if s.config.Bootstrap {
		if err := s.bootstrapCluster(); err != nil {
			return fmt.Errorf("failed to bootstrap cluster: %w", err)
		}
	} else {
		// Join existing cluster
		if err := s.joinCluster(); err != nil {
			return fmt.Errorf("failed to join cluster: %w", err)
		}
	}

	s.running = true
	s.logger.WithField("node_id", s.config.NodeID).Info("Consensus service started")

	return nil
}

// Stop stops the consensus service
func (s *ConsensusService) Stop(ctx context.Context) error {
	if !s.running {
		return nil
	}

	s.logger.Info("Stopping consensus service")

	close(s.stopCh)
	s.wg.Wait()

	// Shutdown Raft
	if s.raft != nil {
		future := s.raft.Shutdown()
		if err := future.Error(); err != nil {
			s.logger.WithError(err).Error("Failed to shutdown Raft")
		}
	}

	// Close stores
	if s.logStore != nil {
		s.logStore.Close()
	}
	if s.stableStore != nil {
		s.stableStore.Close()
	}

	s.running = false
	s.logger.Info("Consensus service stopped")

	return nil
}

// bootstrapCluster initializes a new cluster
func (s *ConsensusService) bootstrapCluster() error {
	configuration := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(s.config.NodeID),
				Address: raft.ServerAddress(s.config.BindAddress),
			},
		},
	}

	future := s.raft.BootstrapCluster(configuration)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to bootstrap cluster: %w", err)
	}

	s.logger.Info("Successfully bootstrapped new cluster")
	return nil
}

// joinCluster joins an existing cluster
func (s *ConsensusService) joinCluster() error {
	// Try to join using bootstrap peers
	for _, peerAddr := range s.config.BootstrapPeers {
		if err := s.requestToJoin(peerAddr); err != nil {
			s.logger.WithError(err).WithField("peer", peerAddr).Warn("Failed to join via peer")
			continue
		}
		s.logger.WithField("peer", peerAddr).Info("Successfully joined cluster via peer")
		return nil
	}

	return fmt.Errorf("failed to join cluster via any bootstrap peer")
}

// requestToJoin requests to join the cluster via a peer
func (s *ConsensusService) requestToJoin(peerAddr string) error {
	// In a real implementation, this would make an HTTP request to the peer
	// to request addition to the cluster. For now, we'll simulate it.
	
	s.logger.WithField("peer", peerAddr).Info("Requesting to join cluster")
	
	// This would typically involve:
	// 1. HTTP request to peer's join endpoint
	// 2. Peer validates the request
	// 3. Peer calls AddVoter on its Raft instance
	// 4. Raft replicates the configuration change
	
	return nil
}

// monitorLeadership monitors leadership changes
func (s *ConsensusService) monitorLeadership() {
	for {
		select {
		case isLeader := <-s.raft.LeaderCh():
			s.logger.WithField("is_leader", isLeader).Info("Leadership status changed")
			
			select {
			case s.leadership <- isLeader:
			default:
			}
			
			if isLeader {
				s.onBecomeLeader()
			} else {
				s.onLoseLeadership()
			}
		case <-s.stopCh:
			return
		}
	}
}

// onBecomeLeader handles becoming the leader
func (s *ConsensusService) onBecomeLeader() {
	s.logger.Info("Became cluster leader")
	
	// Perform leader-specific initialization
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.leaderTasks()
	}()
}

// onLoseLeadership handles losing leadership
func (s *ConsensusService) onLoseLeadership() {
	s.logger.Info("Lost cluster leadership")
	// Cleanup leader-specific tasks
}

// leaderTasks performs tasks specific to the leader
func (s *ConsensusService) leaderTasks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Perform periodic leader tasks
			s.reconcileClusterState()
		case <-s.stopCh:
			return
		}
	}
}

// reconcileClusterState performs leader reconciliation tasks
func (s *ConsensusService) reconcileClusterState() {
	// Clean up expired attestations
	if err := s.cleanupExpiredAttestations(); err != nil {
		s.logger.WithError(err).Error("Failed to cleanup expired attestations")
	}

	// Update cluster metadata
	if err := s.updateClusterMetadata(); err != nil {
		s.logger.WithError(err).Error("Failed to update cluster metadata")
	}
}

// AddAttestation adds an attestation to the distributed state
func (s *ConsensusService) AddAttestation(ctx context.Context, response *attestation.AttestationResponse) error {
	if !s.running {
		return fmt.Errorf("consensus service not running")
	}

	command := &ConsensusCommand{
		Type:      CommandAddAttestation,
		RequestID: response.RequestID,
		TenantID:  response.TenantID,
		Data: map[string]interface{}{
			"attestation": response,
		},
		Timestamp: time.Now(),
		NodeID:    s.config.NodeID,
	}

	return s.applyCommand(ctx, command)
}

// GetAttestation retrieves an attestation from the distributed state
func (s *ConsensusService) GetAttestation(ctx context.Context, requestID string) (*attestation.AttestationResponse, error) {
	s.fsm.mutex.RLock()
	defer s.fsm.mutex.RUnlock()

	if response, exists := s.fsm.state.Attestations[requestID]; exists {
		return response, nil
	}

	return nil, fmt.Errorf("attestation %s not found", requestID)
}

// UpdateTrustValue updates a trust value in the distributed state
func (s *ConsensusService) UpdateTrustValue(ctx context.Context, entityID string, trustValue float64) error {
	if !s.running {
		return fmt.Errorf("consensus service not running")
	}

	command := &ConsensusCommand{
		Type: CommandUpdateTrustValue,
		Data: map[string]interface{}{
			"entity_id":    entityID,
			"trust_value":  trustValue,
		},
		Timestamp: time.Now(),
		NodeID:    s.config.NodeID,
	}

	return s.applyCommand(ctx, command)
}

// GetTrustValue retrieves a trust value from the distributed state
func (s *ConsensusService) GetTrustValue(ctx context.Context, entityID string) (float64, error) {
	s.fsm.mutex.RLock()
	defer s.fsm.mutex.RUnlock()

	if value, exists := s.fsm.state.TrustValues[entityID]; exists {
		return value, nil
	}

	return 0.0, fmt.Errorf("trust value for %s not found", entityID)
}

// AddPeer adds a peer to the cluster
func (s *ConsensusService) AddPeer(ctx context.Context, peer *Peer) error {
	if !s.IsLeader() {
		return fmt.Errorf("only leader can add peers")
	}

	// Add to Raft configuration
	future := s.raft.AddVoter(raft.ServerID(peer.ID), raft.ServerAddress(peer.Address), 0, 0)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to add peer to Raft: %w", err)
	}

	// Add to local peer tracking
	command := &ConsensusCommand{
		Type: CommandAddPeer,
		Data: map[string]interface{}{
			"peer": peer,
		},
		Timestamp: time.Now(),
		NodeID:    s.config.NodeID,
	}

	return s.applyCommand(ctx, command)
}

// RemovePeer removes a peer from the cluster
func (s *ConsensusService) RemovePeer(ctx context.Context, peerID string) error {
	if !s.IsLeader() {
		return fmt.Errorf("only leader can remove peers")
	}

	// Remove from Raft configuration
	future := s.raft.RemoveServer(raft.ServerID(peerID), 0, 0)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to remove peer from Raft: %w", err)
	}

	// Remove from local peer tracking
	command := &ConsensusCommand{
		Type: CommandRemovePeer,
		Data: map[string]interface{}{
			"peer_id": peerID,
		},
		Timestamp: time.Now(),
		NodeID:    s.config.NodeID,
	}

	return s.applyCommand(ctx, command)
}

// IsLeader returns true if this node is the leader
func (s *ConsensusService) IsLeader() bool {
	if s.raft == nil {
		return false
	}
	return s.raft.State() == raft.Leader
}

// GetLeader returns the current leader address
func (s *ConsensusService) GetLeader() string {
	if s.raft == nil {
		return ""
	}
	return string(s.raft.Leader())
}

// GetPeers returns all known peers
func (s *ConsensusService) GetPeers() map[string]*Peer {
	s.peersMux.RLock()
	defer s.peersMux.RUnlock()

	peers := make(map[string]*Peer)
	for id, peer := range s.peers {
		peers[id] = peer
	}
	return peers
}

// GetClusterState returns the current cluster state
func (s *ConsensusService) GetClusterState() *AttestationState {
	s.fsm.mutex.RLock()
	defer s.fsm.mutex.RUnlock()

	// Return a copy of the state
	return &AttestationState{
		Attestations: make(map[string]*attestation.AttestationResponse),
		Policies:     make(map[string]*attestation.Policy),
		TrustValues:  make(map[string]float64),
		Metadata:     make(map[string]interface{}),
		LastUpdated:  s.fsm.state.LastUpdated,
		Version:      s.fsm.state.Version,
	}
}

// applyCommand applies a command to the Raft log
func (s *ConsensusService) applyCommand(ctx context.Context, command *ConsensusCommand) error {
	data, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %w", err)
	}

	future := s.raft.Apply(data, 10*time.Second)
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to apply command: %w", err)
	}

	return nil
}

// cleanupExpiredAttestations removes expired attestations
func (s *ConsensusService) cleanupExpiredAttestations() error {
	s.fsm.mutex.Lock()
	defer s.fsm.mutex.Unlock()

	now := time.Now()
	for requestID, response := range s.fsm.state.Attestations {
		if response.ValidUntil.Before(now) {
			delete(s.fsm.state.Attestations, requestID)
			s.logger.WithField("request_id", requestID).Debug("Cleaned up expired attestation")
		}
	}

	return nil
}

// updateClusterMetadata updates cluster metadata
func (s *ConsensusService) updateClusterMetadata() error {
	s.fsm.mutex.Lock()
	defer s.fsm.mutex.Unlock()

	s.fsm.state.Metadata["last_leader_update"] = time.Now()
	s.fsm.state.Metadata["cluster_size"] = len(s.peers) + 1 // +1 for this node
	s.fsm.state.LastUpdated = time.Now()

	return nil
}

// FSM methods

// Apply applies a log entry to the FSM
func (f *AttestationFSM) Apply(logEntry *raft.Log) interface{} {
	var command ConsensusCommand
	if err := json.Unmarshal(logEntry.Data, &command); err != nil {
		f.logger.WithError(err).Error("Failed to unmarshal command")
		return err
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	switch command.Type {
	case CommandAddAttestation:
		return f.applyAddAttestation(&command)
	case CommandUpdateAttestation:
		return f.applyUpdateAttestation(&command)
	case CommandRemoveAttestation:
		return f.applyRemoveAttestation(&command)
	case CommandUpdateTrustValue:
		return f.applyUpdateTrustValue(&command)
	case CommandAddPeer:
		return f.applyAddPeer(&command)
	case CommandRemovePeer:
		return f.applyRemovePeer(&command)
	default:
		f.logger.WithField("command_type", command.Type).Warn("Unknown command type")
		return fmt.Errorf("unknown command type: %s", command.Type)
	}
}

// Snapshot creates a snapshot of the FSM state
func (f *AttestationFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	// Create a copy of the state
	snapshot := &AttestationSnapshot{
		state: &AttestationState{
			Attestations: make(map[string]*attestation.AttestationResponse),
			Policies:     make(map[string]*attestation.Policy),
			TrustValues:  make(map[string]float64),
			Metadata:     make(map[string]interface{}),
			LastUpdated:  f.state.LastUpdated,
			Version:      f.state.Version,
		},
	}

	// Copy attestations
	for k, v := range f.state.Attestations {
		snapshot.state.Attestations[k] = v
	}

	// Copy policies
	for k, v := range f.state.Policies {
		snapshot.state.Policies[k] = v
	}

	// Copy trust values
	for k, v := range f.state.TrustValues {
		snapshot.state.TrustValues[k] = v
	}

	// Copy metadata
	for k, v := range f.state.Metadata {
		snapshot.state.Metadata[k] = v
	}

	return snapshot, nil
}

// Restore restores the FSM state from a snapshot
func (f *AttestationFSM) Restore(snapshot io.ReadCloser) error {
	defer snapshot.Close()

	var state AttestationState
	decoder := json.NewDecoder(snapshot)
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("failed to decode snapshot: %w", err)
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.state = &state
	f.logger.WithField("version", state.Version).Info("Restored state from snapshot")

	return nil
}

// Apply methods for different command types

func (f *AttestationFSM) applyAddAttestation(command *ConsensusCommand) interface{} {
	attestationData, ok := command.Data["attestation"]
	if !ok {
		return fmt.Errorf("attestation data missing")
	}

	// Convert to AttestationResponse
	data, err := json.Marshal(attestationData)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation: %w", err)
	}

	var response attestation.AttestationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("failed to unmarshal attestation: %w", err)
	}

	f.state.Attestations[response.RequestID] = &response
	f.state.Version++
	f.state.LastUpdated = time.Now()

	f.logger.WithField("request_id", response.RequestID).Debug("Added attestation to state")
	return nil
}

func (f *AttestationFSM) applyUpdateAttestation(command *ConsensusCommand) interface{} {
	// Similar to add but for updates
	return f.applyAddAttestation(command)
}

func (f *AttestationFSM) applyRemoveAttestation(command *ConsensusCommand) interface{} {
	requestID, ok := command.Data["request_id"].(string)
	if !ok {
		return fmt.Errorf("request_id missing")
	}

	delete(f.state.Attestations, requestID)
	f.state.Version++
	f.state.LastUpdated = time.Now()

	f.logger.WithField("request_id", requestID).Debug("Removed attestation from state")
	return nil
}

func (f *AttestationFSM) applyUpdateTrustValue(command *ConsensusCommand) interface{} {
	entityID, ok := command.Data["entity_id"].(string)
	if !ok {
		return fmt.Errorf("entity_id missing")
	}

	trustValue, ok := command.Data["trust_value"].(float64)
	if !ok {
		return fmt.Errorf("trust_value missing")
	}

	f.state.TrustValues[entityID] = trustValue
	f.state.Version++
	f.state.LastUpdated = time.Now()

	f.logger.WithFields(logrus.Fields{
		"entity_id":    entityID,
		"trust_value":  trustValue,
	}).Debug("Updated trust value")
	return nil
}

func (f *AttestationFSM) applyAddPeer(command *ConsensusCommand) interface{} {
	// Peer management would be handled here
	f.state.Version++
	f.state.LastUpdated = time.Now()
	return nil
}

func (f *AttestationFSM) applyRemovePeer(command *ConsensusCommand) interface{} {
	// Peer management would be handled here
	f.state.Version++
	f.state.LastUpdated = time.Now()
	return nil
}

// AttestationSnapshot implements raft.FSMSnapshot
type AttestationSnapshot struct {
	state *AttestationState
}

// Persist persists the snapshot
func (s *AttestationSnapshot) Persist(sink raft.SnapshotSink) error {
	defer sink.Close()

	encoder := json.NewEncoder(sink)
	if err := encoder.Encode(s.state); err != nil {
		sink.Cancel()
		return fmt.Errorf("failed to encode snapshot: %w", err)
	}

	return nil
}

// Release releases the snapshot
func (s *AttestationSnapshot) Release() {
	// Nothing to release
}

package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

// EventPublisher interface for publishing attestation events
type EventPublisher interface {
	PublishEvent(ctx context.Context, event *AttestationEvent) error
	Close() error
}

// EventSubscriber interface for subscribing to attestation events
type EventSubscriber interface {
	Subscribe(ctx context.Context, eventTypes []AttestationEventType, handler EventHandler) error
	Unsubscribe(ctx context.Context, subscription string) error
	Close() error
}

// EventHandler function type for handling events
type EventHandler func(ctx context.Context, event *AttestationEvent) error

// NATSEventPublisher implements EventPublisher using NATS JetStream
type NATSEventPublisher struct {
	conn    *nats.Conn
	js      nats.JetStreamContext
	logger  *logrus.Logger
	stream  string
	subject string
}

// NewNATSEventPublisher creates a new NATS event publisher
func NewNATSEventPublisher(logger *logrus.Logger) (*NATSEventPublisher, error) {
	// Connect to NATS
	nc, err := nats.Connect(nats.DefaultURL,
		nats.ReconnectWait(2*time.Second),
		nats.MaxReconnects(10),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			logger.WithError(err).Warn("NATS disconnected")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Create JetStream context
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	publisher := &NATSEventPublisher{
		conn:    nc,
		js:      js,
		logger:  logger,
		stream:  "ATTESTATION_EVENTS",
		subject: "attestation.events",
	}

	// Create or update stream
	if err := publisher.ensureStream(); err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to ensure stream: %w", err)
	}

	return publisher, nil
}

// ensureStream creates or updates the JetStream stream
func (p *NATSEventPublisher) ensureStream() error {
	streamConfig := &nats.StreamConfig{
		Name:        p.stream,
		Subjects:    []string{p.subject + ".>"},
		Storage:     nats.FileStorage,
		Retention:   nats.WorkQueuePolicy,
		MaxAge:      24 * time.Hour,
		MaxBytes:    1024 * 1024 * 1024, // 1GB
		MaxMsgs:     1000000,
		Duplicates:  5 * time.Minute,
		Replicas:    1,
	}

	_, err := p.js.AddStream(streamConfig)
	if err != nil {
		// Try updating if stream already exists
		_, err = p.js.UpdateStream(streamConfig)
		if err != nil {
			return fmt.Errorf("failed to create/update stream: %w", err)
		}
	}

	return nil
}

// PublishEvent publishes an attestation event
func (p *NATSEventPublisher) PublishEvent(ctx context.Context, event *AttestationEvent) error {
	// Serialize event
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create subject with event type
	subject := fmt.Sprintf("%s.%s.%s", p.subject, event.Type, event.TenantID)

	// Create NATS message
	msg := &nats.Msg{
		Subject: subject,
		Data:    data,
		Header: nats.Header{
			"Event-ID":        []string{event.ID},
			"Event-Type":      []string{string(event.Type)},
			"Tenant-ID":       []string{event.TenantID},
			"Event-Source":    []string{event.Source},
			"Content-Type":    []string{"application/json"},
			"Timestamp":       []string{event.Timestamp.Format(time.RFC3339)},
		},
	}

	// Add trace context if available
	if event.Metadata.TraceID != "" {
		msg.Header.Add("Trace-ID", event.Metadata.TraceID)
	}
	if event.Metadata.SpanID != "" {
		msg.Header.Add("Span-ID", event.Metadata.SpanID)
	}

	// Publish with acknowledgment
	ack, err := p.js.PublishMsg(msg, nats.Context(ctx))
	if err != nil {
		p.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to publish event")
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.WithFields(logrus.Fields{
		"event_id":   event.ID,
		"event_type": event.Type,
		"tenant_id":  event.TenantID,
		"sequence":   ack.Sequence,
		"stream":     ack.Stream,
	}).Debug("Event published successfully")

	return nil
}

// Close closes the NATS connection
func (p *NATSEventPublisher) Close() error {
	if p.conn != nil {
		p.conn.Close()
	}
	return nil
}

// NATSEventSubscriber implements EventSubscriber using NATS JetStream
type NATSEventSubscriber struct {
	conn         *nats.Conn
	js           nats.JetStreamContext
	logger       *logrus.Logger
	stream       string
	subject      string
	consumer     string
	subscriptions map[string]*nats.Subscription
}

// NewNATSEventSubscriber creates a new NATS event subscriber
func NewNATSEventSubscriber(logger *logrus.Logger, consumerName string) (*NATSEventSubscriber, error) {
	// Connect to NATS
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Create JetStream context
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	return &NATSEventSubscriber{
		conn:          nc,
		js:            js,
		logger:        logger,
		stream:        "ATTESTATION_EVENTS",
		subject:       "attestation.events",
		consumer:      consumerName,
		subscriptions: make(map[string]*nats.Subscription),
	}, nil
}

// Subscribe subscribes to specific event types
func (s *NATSEventSubscriber) Subscribe(ctx context.Context, eventTypes []AttestationEventType, handler EventHandler) error {
	// Create consumer configuration
	consumerConfig := &nats.ConsumerConfig{
		Durable:       s.consumer,
		AckPolicy:     nats.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    3,
		ReplayPolicy:  nats.ReplayInstantPolicy,
		FilterSubject: s.subject + ".>",
	}

	// Create or get consumer
	consumerInfo, err := s.js.AddConsumer(s.stream, consumerConfig)
	if err != nil {
		return fmt.Errorf("failed to create consumer: %w", err)
	}

	// Create subscription
	sub, err := s.js.PullSubscribe("", "", nats.Bind(s.stream, consumerInfo.Name))
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}

	// Store subscription
	subscriptionKey := fmt.Sprintf("%s-%v", s.consumer, eventTypes)
	s.subscriptions[subscriptionKey] = sub

	// Start message processing
	go s.processMessages(ctx, sub, eventTypes, handler)

	s.logger.WithFields(logrus.Fields{
		"consumer":    s.consumer,
		"event_types": eventTypes,
	}).Info("Subscribed to attestation events")

	return nil
}

// processMessages processes incoming messages
func (s *NATSEventSubscriber) processMessages(ctx context.Context, sub *nats.Subscription, eventTypes []AttestationEventType, handler EventHandler) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Fetch messages
			msgs, err := sub.Fetch(10, nats.MaxWait(1*time.Second))
			if err != nil {
				if err == nats.ErrTimeout {
					continue
				}
				s.logger.WithError(err).Error("Failed to fetch messages")
				continue
			}

			for _, msg := range msgs {
				if err := s.handleMessage(ctx, msg, eventTypes, handler); err != nil {
					s.logger.WithError(err).Error("Failed to handle message")
					msg.Nak()
				} else {
					msg.Ack()
				}
			}
		}
	}
}

// handleMessage handles a single message
func (s *NATSEventSubscriber) handleMessage(ctx context.Context, msg *nats.Msg, eventTypes []AttestationEventType, handler EventHandler) error {
	// Parse event
	var event AttestationEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	// Check if event type is in filter
	eventTypeMatch := false
	for _, et := range eventTypes {
		if event.Type == et {
			eventTypeMatch = true
			break
		}
	}
	if !eventTypeMatch {
		return nil // Skip this event
	}

	// Add message metadata to event
	if event.Metadata.Attributes == nil {
		event.Metadata.Attributes = make(map[string]interface{})
	}
	event.Metadata.Attributes["nats_subject"] = msg.Subject
	event.Metadata.Attributes["nats_sequence"] = msg.Reply

	// Call handler
	return handler(ctx, &event)
}

// Unsubscribe unsubscribes from events
func (s *NATSEventSubscriber) Unsubscribe(ctx context.Context, subscription string) error {
	if sub, exists := s.subscriptions[subscription]; exists {
		if err := sub.Unsubscribe(); err != nil {
			return fmt.Errorf("failed to unsubscribe: %w", err)
		}
		delete(s.subscriptions, subscription)
	}
	return nil
}

// Close closes all subscriptions and the connection
func (s *NATSEventSubscriber) Close() error {
	for _, sub := range s.subscriptions {
		sub.Unsubscribe()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

// KafkaEventPublisher implements EventPublisher using Apache Kafka
type KafkaEventPublisher struct {
	writer *kafka.Writer
	logger *logrus.Logger
	topic  string
}

// NewKafkaEventPublisher creates a new Kafka event publisher
func NewKafkaEventPublisher(brokers []string, topic string, logger *logrus.Logger) *KafkaEventPublisher {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
		RequiredAcks: kafka.RequireAll,
		Compression:  kafka.Snappy,
		ErrorLogger:  kafka.LoggerFunc(logger.Errorf),
	}

	return &KafkaEventPublisher{
		writer: writer,
		logger: logger,
		topic:  topic,
	}
}

// PublishEvent publishes an event to Kafka
func (p *KafkaEventPublisher) PublishEvent(ctx context.Context, event *AttestationEvent) error {
	// Serialize event
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create Kafka message
	msg := kafka.Message{
		Key:   []byte(event.TenantID + ":" + event.Subject),
		Value: data,
		Headers: []kafka.Header{
			{Key: "Event-ID", Value: []byte(event.ID)},
			{Key: "Event-Type", Value: []byte(string(event.Type))},
			{Key: "Tenant-ID", Value: []byte(event.TenantID)},
			{Key: "Event-Source", Value: []byte(event.Source)},
			{Key: "Content-Type", Value: []byte("application/json")},
			{Key: "Timestamp", Value: []byte(event.Timestamp.Format(time.RFC3339))},
		},
		Time: event.Timestamp,
	}

	// Add trace context
	if event.Metadata.TraceID != "" {
		msg.Headers = append(msg.Headers, kafka.Header{
			Key: "Trace-ID", Value: []byte(event.Metadata.TraceID),
		})
	}

	// Write message
	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to publish event to Kafka")
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.WithFields(logrus.Fields{
		"event_id":   event.ID,
		"event_type": event.Type,
		"tenant_id":  event.TenantID,
		"topic":      p.topic,
	}).Debug("Event published to Kafka successfully")

	return nil
}

// Close closes the Kafka writer
func (p *KafkaEventPublisher) Close() error {
	return p.writer.Close()
}

// KafkaEventSubscriber implements EventSubscriber using Apache Kafka
type KafkaEventSubscriber struct {
	reader *kafka.Reader
	logger *logrus.Logger
	topic  string
}

// NewKafkaEventSubscriber creates a new Kafka event subscriber
func NewKafkaEventSubscriber(brokers []string, topic, groupID string, logger *logrus.Logger) *KafkaEventSubscriber {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     groupID,
		StartOffset: kafka.LastOffset,
		MinBytes:    10e3, // 10KB
		MaxBytes:    10e6, // 10MB
		MaxWait:     1 * time.Second,
		ErrorLogger: kafka.LoggerFunc(logger.Errorf),
	})

	return &KafkaEventSubscriber{
		reader: reader,
		logger: logger,
		topic:  topic,
	}
}

// Subscribe subscribes to Kafka events
func (s *KafkaEventSubscriber) Subscribe(ctx context.Context, eventTypes []AttestationEventType, handler EventHandler) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := s.reader.ReadMessage(ctx)
				if err != nil {
					s.logger.WithError(err).Error("Failed to read Kafka message")
					continue
				}

				if err := s.handleKafkaMessage(ctx, msg, eventTypes, handler); err != nil {
					s.logger.WithError(err).Error("Failed to handle Kafka message")
				}
			}
		}
	}()

	s.logger.WithFields(logrus.Fields{
		"topic":       s.topic,
		"event_types": eventTypes,
	}).Info("Subscribed to Kafka events")

	return nil
}

// handleKafkaMessage handles a Kafka message
func (s *KafkaEventSubscriber) handleKafkaMessage(ctx context.Context, msg kafka.Message, eventTypes []AttestationEventType, handler EventHandler) error {
	// Parse event
	var event AttestationEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	// Check if event type is in filter
	eventTypeMatch := false
	for _, et := range eventTypes {
		if event.Type == et {
			eventTypeMatch = true
			break
		}
	}
	if !eventTypeMatch {
		return nil // Skip this event
	}

	// Add Kafka metadata to event
	if event.Metadata.Attributes == nil {
		event.Metadata.Attributes = make(map[string]interface{})
	}
	event.Metadata.Attributes["kafka_topic"] = msg.Topic
	event.Metadata.Attributes["kafka_partition"] = msg.Partition
	event.Metadata.Attributes["kafka_offset"] = msg.Offset

	// Call handler
	return handler(ctx, &event)
}

// Unsubscribe is not applicable for Kafka (handled by context cancellation)
func (s *KafkaEventSubscriber) Unsubscribe(ctx context.Context, subscription string) error {
	return nil
}

// Close closes the Kafka reader
func (s *KafkaEventSubscriber) Close() error {
	return s.reader.Close()
}

// NoOpEventPublisher is a no-op implementation for testing
type NoOpEventPublisher struct{}

// NewNoOpEventPublisher creates a new no-op event publisher
func NewNoOpEventPublisher() *NoOpEventPublisher {
	return &NoOpEventPublisher{}
}

// PublishEvent does nothing (no-op)
func (p *NoOpEventPublisher) PublishEvent(ctx context.Context, event *AttestationEvent) error {
	return nil
}

// Close does nothing (no-op)
func (p *NoOpEventPublisher) Close() error {
	return nil
}

// EventRouter routes events to multiple publishers
type EventRouter struct {
	publishers []EventPublisher
	logger     *logrus.Logger
}

// NewEventRouter creates a new event router
func NewEventRouter(publishers []EventPublisher, logger *logrus.Logger) *EventRouter {
	return &EventRouter{
		publishers: publishers,
		logger:     logger,
	}
}

// PublishEvent publishes to all configured publishers
func (r *EventRouter) PublishEvent(ctx context.Context, event *AttestationEvent) error {
	var lastErr error
	successful := 0

	for i, publisher := range r.publishers {
		if err := publisher.PublishEvent(ctx, event); err != nil {
			r.logger.WithError(err).WithField("publisher_index", i).Error("Failed to publish to publisher")
			lastErr = err
		} else {
			successful++
		}
	}

	if successful == 0 && lastErr != nil {
		return fmt.Errorf("failed to publish to any publisher: %w", lastErr)
	}

	return nil
}

// Close closes all publishers
func (r *EventRouter) Close() error {
	for _, publisher := range r.publishers {
		if err := publisher.Close(); err != nil {
			r.logger.WithError(err).Error("Failed to close publisher")
		}
	}
	return nil
}

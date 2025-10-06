# Enterprise-grade Distributed System Health Monitor

> 🌟 **Live Demo**: [https://health-monitor-demo.railway.app](https://health-monitor-demo.railway.app) (Deploy your own below!)

A comprehensive, enterprise-ready distributed system health monitor with RATS-compliant attestation framework, ML-based anomaly detection, hardware-backed attestation, and multi-cloud federation support.

## 🚀 Quick Deploy

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/NvLBDl?referralCode=alphasec)
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)
[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)

> **Resume-Ready**: Use the live deployment URL from above in your resume to showcase this project to employers!

## 🚀 Features

### Core Capabilities
- **RATS-Compliant Attestation**: Full implementation of Remote Attestation Procedures (RATS) architecture
- **CoRIM Integration**: Concise Reference Integrity Manifest (CoRIM) support for standardized reference value management
- **Event-Driven Architecture**: Real-time attestation events using NATS JetStream and Apache Kafka
- **ML-Based Anomaly Detection**: Container behavior drift detection using Isolation Forest algorithm
- **Hardware-Backed Attestation**: TPM 2.0, Intel TXT, and AMD SVM support
- **Multi-Cloud Federation**: AWS Nitro Enclaves, Azure Confidential Computing, GCP Shielded VMs
- **Sub-10ms Latency**: High-performance attestation with Redis caching and optimized processing
- **Enterprise Observability**: Comprehensive Prometheus metrics and OpenTelemetry tracing

### Security & Compliance
- **NIST 800-155** compliance for BIOS/boot integrity
- **SLSA Level 4** supply chain security integration
- **SPIFFE/SPIRE** workload identity framework
- **Confidential Containers** support for runtime attestation
- **Zero-trust architecture** with continuous verification

### Multi-Cloud Support
- **AWS**: Nitro Enclaves, EC2 instance attestation, IAM integration
- **Azure**: Confidential VMs, Trusted Launch, vTPM attestation
- **GCP**: Shielded VMs, Confidential Computing, integrity monitoring
- **Cross-cloud consensus** for federated attestation verification

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enterprise Health Monitor                     │
├─────────────────────────────────────────────────────────────────┤
│                     Application Layer                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   REST API  │ │  WebSocket  │ │   CLI Tool  │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│                      Core Services                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │ Attestation │ │  Federation │ │  Consensus  │              │
│  │   Service   │ │   Manager   │ │   Service   │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│                    Specialized Components                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │  ML Anomaly │ │  Hardware   │ │   Policy    │              │
│  │  Detection  │ │  Attestor   │ │   Engine    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │    Redis    │ │    NATS     │ │    Raft     │              │
│  │   Cluster   │ │ JetStream   │ │ Consensus   │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- **Go 1.21+**: Primary development language
- **Redis 7.0+**: Evidence caching and session management
- **NATS 2.9+**: Event streaming and real-time messaging
- **TPM 2.0**: Hardware security module (for hardware attestation)
- **Docker**: Container runtime for deployment

### Cloud Provider Requirements
- **AWS**: EC2 instances with Nitro System support
- **Azure**: VMs with Trusted Launch or Confidential VM features
- **GCP**: Compute instances with Shielded VM or Confidential Computing

## 🚀 Quick Start

### Option 1: Live Demo (Resume Ready! 🎯)

**Deploy to the cloud in 2 minutes** and get a live URL for your resume:

1. **Netlify** (Fastest): Click [![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)
2. **Railway**: Click [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/NvLBDl?referralCode=alphasec)
3. **Heroku**: Click [![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)
4. **Render**: Click [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)

After deployment, add your live URL to your resume:
> **📝 Resume Example**: "Live Demo: https://your-app-name.railway.app"

### Option 2: Local Development

```bash
git clone https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor.git
cd Distributed-System-Health-Monitor

# Quick start with Docker Compose
docker-compose up --build

# OR build locally
go build -o health-monitor cmd/main.go
```

### 2. Configuration

Create a configuration file `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: true
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"

attestation:
  enabled: true
  max_concurrent_requests: 1000
  request_timeout: 30s
  
  # Evidence caching configuration
  cache:
    type: "redis"
    redis:
      addresses: ["localhost:6379"]
      cluster_mode: false
      password: ""
      db: 0
      max_retries: 3
      pool_size: 100
    ttl: 3600s
    
  # Event streaming
  events:
    enabled: true
    provider: "nats"
    nats:
      url: "nats://localhost:4222"
      cluster: true
      jetstream: true
      subjects:
        attestation_requests: "attestation.requests"
        attestation_results: "attestation.results"
        anomaly_alerts: "anomaly.alerts"

  # Policy engine
  policy_engine:
    enabled: true
    type: "opa"
    policy_paths:
      - "./policies"
    plugins:
      - "nist_800_155"
      - "slsa_level_4"
      - "compliance"

# ML-based anomaly detection
ml:
  enabled: true
  detector_type: "isolation_forest"
  config:
    num_trees: 100
    max_depth: 10
    contamination: 0.1
    anomaly_threshold: 0.6
    enabled_features:
      - "cpu_usage"
      - "memory_usage"
      - "network_rx"
      - "network_tx"
      - "syscall_count"
      - "privileged_ops"

# Hardware attestation
hardware:
  enabled: true
  tpm_path: "/dev/tpm0"
  pcr_selection: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  hash_algorithm: "SHA256"

# Multi-cloud federation
federation:
  enabled: true
  listen_address: ":8443"
  timeout: 30s
  consensus_threshold: 0.6
  min_consensus: 2
  
  # AWS configuration
  aws:
    enabled: true
    region: "us-west-2"
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_key: "${AWS_SECRET_ACCESS_KEY}"
    
  # Azure configuration
  azure:
    enabled: true
    subscription_id: "${AZURE_SUBSCRIPTION_ID}"
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    region: "West US 2"
    
  # GCP configuration
  gcp:
    enabled: true
    project_id: "${GCP_PROJECT_ID}"
    region: "us-west1"
    service_account_key: "${GCP_SERVICE_ACCOUNT_KEY}"

# Consensus configuration
consensus:
  enabled: true
  node_id: "node-1"
  listen_address: ":8080"
  data_dir: "./raft-data"
  peers:
    - "node-1:8080"
    - "node-2:8080"
    - "node-3:8080"

# Observability
metrics:
  enabled: true
  listen_address: ":9090"
  path: "/metrics"

tracing:
  enabled: true
  service_name: "health-monitor"
  endpoint: "http://localhost:14268/api/traces"
  sample_rate: 0.1

# Logging
logging:
  level: "info"
  format: "json"
  output: "stdout"

# CoRIM Integration
corim:
  enabled: true
  redis:
    address: "localhost:6379"
    password: ""
    database: 0
    key_prefix: "corim:"
    default_ttl: "24h"
  parser:
    max_file_size: 10485760  # 10MB
    validate_on_load: true
    strict_mode: false
    enable_metrics: true
    enable_debug_logs: false
  provisioner:
    max_profiles: 1000
    enable_bulk_operations: true
    auto_refresh_interval: "1h"
```

### 3. Start Required Services

```bash
# Start Redis
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Start NATS with JetStream
docker run -d --name nats -p 4222:4222 nats:2.9-alpine -js

# Optional: Start Jaeger for tracing
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14268:14268 \
  jaegertracing/all-in-one:latest
```

### 4. Run the Application

```bash
# Start the health monitor
./health-monitor --config config.yaml

# Or run with specific log level
./health-monitor --config config.yaml --log-level debug
```

## 📖 API Documentation

### Core Endpoints

#### POST /api/v1/attestation/request
Submit an attestation request for verification.

```bash
curl -X POST https://localhost:8443/api/v1/attestation/request \
  -H "Content-Type: application/json" \
  -d '{
    "evidence": {
      "type": "TPM_QUOTE",
      "data": "base64-encoded-evidence",
      "nonce": "random-challenge"
    },
    "policy_id": "default",
    "tenant_id": "tenant-1"
  }'
```

#### GET /api/v1/attestation/{id}
Retrieve attestation results by ID.

```bash
curl https://localhost:8443/api/v1/attestation/abc123
```

#### GET /api/v1/attestation/{id}/status
Get the current status of an attestation request.

```bash
curl https://localhost:8443/api/v1/attestation/abc123/status
```

### Federation Endpoints

#### GET /api/v1/cluster/status
Get the current cluster status and consensus information.

```bash
curl https://localhost:8443/api/v1/cluster/status
```

#### GET /api/v1/cluster/peers
List all cluster peers and their status.

```bash
curl https://localhost:8443/api/v1/cluster/peers
```

### CoRIM Endpoints

> 💡 **Try it live**: Replace `localhost:8080` with your deployment URL (e.g., `your-app.railway.app`)

#### POST /api/v1/corim/profiles
Upload a new CoRIM profile.

```bash
# Local development
curl -X POST http://localhost:8080/api/v1/corim/profiles \
  -H "Content-Type: application/corim+cbor" \
  --data-binary @examples/sample_corim_profile.cbor

# Live demo (use your deployment URL)
curl -X POST https://your-app.railway.app/api/v1/corim/profiles \
  -H "Content-Type: application/corim+cbor" \
  --data-binary @examples/sample_corim_profile.cbor
```

#### GET /api/v1/corim/profiles
List all CoRIM profiles.

```bash
# Local
curl http://localhost:8080/api/v1/corim/profiles

# Live demo
curl https://your-app.railway.app/api/v1/corim/profiles
```

#### POST /api/v1/corim/reference-values/query
Query reference values by environment.

```bash
curl -X POST https://localhost:8443/api/v1/corim/reference-values/query \
  -H "Content-Type: application/json" \
  -d '{
    "environment": {
      "class": "TPM",
      "vendor": "Infineon",
      "model": "SLB9670"
    }
  }'
```

#### GET /api/v1/corim/health
CoRIM subsystem health check.

```bash
curl https://localhost:8443/api/v1/corim/health
```

### Policy Management

#### GET /api/v1/policies
List all available attestation policies.

```bash
curl https://localhost:8443/api/v1/policies
```

#### GET /api/v1/policies/{id}
Get details for a specific policy.

```bash
curl https://localhost:8443/api/v1/policies/nist-800-155
```

### Health and Monitoring

#### GET /health
Health check endpoint.

```bash
curl https://localhost:8443/health
```

#### GET /ready
Readiness check endpoint.

```bash
curl https://localhost:8443/ready
```

#### GET /metrics
Prometheus metrics endpoint.

```bash
curl https://localhost:8443/metrics
```

## 🔧 Configuration Reference

### Server Configuration
- `server.host`: Listen address (default: "0.0.0.0")
- `server.port`: Listen port (default: 8443)
- `server.tls.enabled`: Enable TLS (default: true)
- `server.read_timeout`: Request read timeout
- `server.write_timeout`: Response write timeout

### Attestation Configuration
- `attestation.enabled`: Enable attestation service
- `attestation.max_concurrent_requests`: Maximum concurrent requests
- `attestation.request_timeout`: Request processing timeout
- `attestation.tenant_isolation`: Enable multi-tenant isolation

### Cache Configuration
- `attestation.cache.type`: Cache backend (redis, memory)
- `attestation.cache.ttl`: Evidence TTL
- `attestation.cache.redis.*`: Redis-specific settings

### ML Configuration
- `ml.detector_type`: Anomaly detector type (isolation_forest)
- `ml.config.num_trees`: Number of isolation trees
- `ml.config.contamination`: Expected outlier fraction
- `ml.config.enabled_features`: Feature list for detection

### Hardware Configuration
- `hardware.tpm_path`: TPM device path
- `hardware.pcr_selection`: PCR registers to read
- `hardware.hash_algorithm`: Hash algorithm for PCR values

### Federation Configuration
- `federation.consensus_threshold`: Minimum agreement for trust
- `federation.min_consensus`: Minimum participating clouds
- `federation.timeout`: Federation request timeout

## 🏭 Deployment

### Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o health-monitor cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/health-monitor .
COPY --from=builder /app/configs/ ./configs/

EXPOSE 8443
CMD ["./health-monitor", "--config", "configs/config.yaml"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: health-monitor
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: health-monitor
  template:
    metadata:
      labels:
        app: health-monitor
    spec:
      serviceAccountName: health-monitor
      containers:
      - name: health-monitor
        image: health-monitor:latest
        ports:
        - containerPort: 8443
          name: https
        - containerPort: 9090
          name: metrics
        env:
        - name: CONFIG_PATH
          value: "/etc/config/config.yaml"
        volumeMounts:
        - name: config
          mountPath: /etc/config
        - name: tpm
          mountPath: /dev/tpm0
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: health-monitor-config
      - name: tpm
        hostPath:
          path: /dev/tpm0
```

### Helm Chart

Create a Helm chart for easy deployment:

```yaml
# values.yaml
replicaCount: 3

image:
  repository: health-monitor
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8443
  targetPort: 8443

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
  - host: health-monitor.company.com
    paths:
    - path: /
      pathType: Prefix
  tls:
  - secretName: health-monitor-tls
    hosts:
    - health-monitor.company.com

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

## 📊 Monitoring and Observability

### Prometheus Metrics

Key metrics exposed:

- `attestation_requests_total`: Total attestation requests
- `attestation_requests_duration_seconds`: Request processing time
- `attestation_verification_results_total`: Verification results by status
- `ml_anomaly_detections_total`: Total anomaly detections
- `federation_consensus_agreement_ratio`: Cross-cloud agreement ratio
- `hardware_attestation_success_rate`: Hardware attestation success rate
- `cache_hit_ratio`: Evidence cache efficiency
- `policy_evaluation_duration_seconds`: Policy evaluation time

### Grafana Dashboards

Import the provided Grafana dashboard for comprehensive monitoring:

```json
{
  "dashboard": {
    "title": "Health Monitor - Security Dashboard",
    "panels": [
      {
        "title": "Attestation Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(attestation_verification_results_total{status=\"success\"}[5m])"
          }
        ]
      },
      {
        "title": "Anomaly Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ml_anomaly_detections_total[5m])"
          }
        ]
      },
      {
        "title": "Multi-Cloud Consensus",
        "type": "heatmap",
        "targets": [
          {
            "expr": "federation_consensus_agreement_ratio"
          }
        ]
      }
    ]
  }
}
```

### Alerting Rules

```yaml
# alerting-rules.yaml
groups:
- name: health-monitor
  rules:
  - alert: AttestationFailureRate
    expr: rate(attestation_verification_results_total{status="failure"}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High attestation failure rate detected"
      description: "Attestation failure rate is {{ $value }} over the last 5 minutes"

  - alert: AnomalyDetectionSpike
    expr: rate(ml_anomaly_detections_total[5m]) > 10
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Anomaly detection spike"
      description: "Unusual number of anomalies detected: {{ $value }}/min"

  - alert: FederationConsensusLow
    expr: federation_consensus_agreement_ratio < 0.6
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Low federation consensus"
      description: "Cross-cloud consensus is only {{ $value }}"
```

## 🧪 Testing

### Unit Tests

```bash
# Run all unit tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration Tests

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
go test -tags=integration ./test/integration/...

# Cleanup
docker-compose -f docker-compose.test.yml down
```

### Load Testing

```bash
# Install hey load testing tool
go install github.com/rakyll/hey@latest

# Test attestation endpoint
hey -n 1000 -c 10 -m POST \
  -H "Content-Type: application/json" \
  -d @test/data/attestation-request.json \
  https://localhost:8443/api/v1/attestation/request
```

## 🔐 Security Considerations

### Authentication and Authorization
- Implement mTLS for client authentication
- Use RBAC for fine-grained access control
- Integrate with existing identity providers (OIDC/SAML)

### Network Security
- Deploy behind a Web Application Firewall (WAF)
- Use private networks for cloud provider communication
- Enable VPC flow logs for network monitoring

### Data Protection
- Encrypt sensitive evidence data at rest
- Use secure key management (AWS KMS, Azure Key Vault, etc.)
- Implement data retention and purging policies

### Compliance
- Regular security audits and penetration testing
- SOC 2 Type II compliance documentation
- FIPS 140-2 Level 2 compliance for cryptographic operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/sast-scan@latest

# Run linting
golangci-lint run

# Run security scan
sast-scan
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## � For Your Resume

**Perfect for showcasing to employers!** This project demonstrates:

✅ **Enterprise Architecture**: Microservices, distributed systems, cloud-native design  
✅ **Advanced Security**: Hardware attestation, zero-trust architecture, cryptographic validation  
✅ **Modern Tech Stack**: Go, Redis, NATS, Kubernetes, Docker, Prometheus  
✅ **Industry Standards**: NIST, RATS, CoRIM, SPIFFE compliance  
✅ **DevOps Excellence**: CI/CD, monitoring, observability, infrastructure-as-code  
✅ **Production Ready**: Live deployment with comprehensive documentation  

**Resume Line Example:**
> "Developed enterprise-grade distributed system health monitor with CoRIM attestation integration, deployed on Railway/Heroku with Redis clustering and NATS messaging. [Live Demo](https://your-app.railway.app) | [GitHub](https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor)"

## 🆘 Support

- **Live Demo**: Use any of the deployment buttons above to create your own instance
- **Issues**: [GitHub Issues](https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor/issues)
- **Documentation**: See [DEPLOYMENT.md](DEPLOYMENT.md) and [RUNBOOK.md](RUNBOOK.md)
- **Cloud Deployment**: Run `./scripts/cloud-deploy.sh` for deployment guidance

## 🙏 Acknowledgments

- [RATS Working Group](https://datatracker.ietf.org/wg/rats/) for attestation standards
- [Open Policy Agent](https://www.openpolicyagent.org/) for policy engine
- [Cloud Native Computing Foundation](https://www.cncf.io/) for cloud-native best practices
- [NIST](https://www.nist.gov/) for security frameworks and guidelines

---

**Built with ❤️ for enterprise security teams**

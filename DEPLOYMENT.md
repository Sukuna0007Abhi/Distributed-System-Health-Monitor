# Health Monitor Deployment Guide

This guide covers deploying the Distributed System Health Monitor with CoRIM integration to various environments.

## 🚀 Quick Start with Docker Compose

### Prerequisites
- Docker Engine 24.0+
- Docker Compose v2.0+
- At least 4GB RAM available
- 10GB disk space

### Local Development Deployment

1. **Clone and build the application:**
   ```bash
   git clone <repository-url>
   cd Distributed-System-Health-Monitor
   docker-compose up --build
   ```

2. **Verify deployment:**
   ```bash
   # Check health status
   curl http://localhost:8080/health
   
   # Access Grafana dashboard
   open http://localhost:3000  # admin/admin
   
   # View Prometheus metrics
   open http://localhost:9090
   ```

3. **Test CoRIM functionality:**
   ```bash
   # Upload a CoRIM profile (example provided)
   curl -X POST http://localhost:8080/api/v1/corim/profiles \
     -H "Content-Type: application/corim+cbor" \
     --data-binary @examples/sample_corim_profile.cbor
   
   # List profiles
   curl http://localhost:8080/api/v1/corim/profiles
   ```

## ☸️ Kubernetes Production Deployment

### Prerequisites
- Kubernetes cluster 1.24+
- kubectl configured
- Ingress controller (NGINX recommended)
- Cert-manager for TLS (optional)
- Prometheus Operator (optional)

### Step-by-Step Kubernetes Deployment

1. **Create namespace:**
   ```bash
   kubectl apply -f deployments/k8s/ingress-hpa-pdb.yaml
   ```

2. **Deploy Redis (persistent storage):**
   ```bash
   kubectl apply -f deployments/k8s/redis.yaml
   ```

3. **Deploy NATS (messaging):**
   ```bash
   kubectl apply -f deployments/k8s/nats.yaml
   ```

4. **Build and push container image:**
   ```bash
   # Build the image
   docker build -t health-monitor:latest .
   
   # Tag and push to your registry
   docker tag health-monitor:latest your-registry.com/health-monitor:v1.0.0
   docker push your-registry.com/health-monitor:v1.0.0
   ```

5. **Deploy the health monitor:**
   ```bash
   # Update image reference in health-monitor.yaml
   sed -i 's|health-monitor:latest|your-registry.com/health-monitor:v1.0.0|g' \
     deployments/k8s/health-monitor.yaml
   
   kubectl apply -f deployments/k8s/health-monitor.yaml
   ```

6. **Configure ingress (update domain):**
   ```bash
   # Edit the ingress configuration
   vim deployments/k8s/ingress-hpa-pdb.yaml
   # Change "health-monitor.example.com" to your domain
   
   kubectl apply -f deployments/k8s/ingress-hpa-pdb.yaml
   ```

### Monitoring Setup

The deployment includes comprehensive monitoring:

- **Prometheus**: Metrics collection
- **Grafana**: Visualization and dashboards
- **Custom metrics**: CoRIM-specific monitoring

Access monitoring:
```bash
# Port-forward Grafana (if not using ingress)
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Port-forward Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090
```

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection string | `redis://redis:6379` |
| `NATS_URL` | NATS server URL | `nats://nats:4222` |
| `LOG_LEVEL` | Logging level | `info` |
| `ENVIRONMENT` | Environment name | `development` |
| `SERVER_PORT` | HTTP server port | `8080` |
| `METRICS_PORT` | Metrics endpoint port | `8081` |

### CoRIM Configuration

The CoRIM integration supports various configuration options in the ConfigMap:

```yaml
corim:
  storage:
    type: "redis"           # Storage backend (redis)
    ttl: "24h"             # Profile TTL
  validation:
    strict_mode: true      # Strict validation mode
    max_profile_size: "50MB"  # Maximum profile size
    allowed_mime_types:
      - "application/corim+cbor"
      - "application/json"
```

## 🔒 Security Considerations

### Network Policies
Network policies are included to restrict traffic between components:
- Health monitor can only access Redis and NATS
- External access only through ingress
- Monitoring access restricted to Prometheus

### RBAC and Security Context
- Non-root containers
- Read-only root filesystem
- Minimal capabilities
- Service accounts with least privilege

### Secrets Management
- Redis password stored in Kubernetes secret
- TLS certificates managed by cert-manager
- Consider using HashiCorp Vault or similar for production

## 📊 Monitoring and Observability

### Key Metrics
- `corim_profiles_total`: Total number of CoRIM profiles
- `corim_validation_duration_seconds`: Profile validation latency
- `corim_storage_operations_total`: Storage operation counters
- `http_requests_duration_seconds`: HTTP request metrics

### Health Checks
- Liveness probe: `/health` endpoint
- Readiness probe: `/health` endpoint with dependency checks
- Startup probe: Configurable delay for slow starts

### Log Management
Structured JSON logging with correlation IDs:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "msg": "CoRIM profile validated",
  "profile_id": "12345",
  "validation_time_ms": 45,
  "trace_id": "abc123"
}
```

## 🚨 Troubleshooting

### Common Issues

1. **Pod startup failures:**
   ```bash
   kubectl describe pod -n health-monitor -l app=health-monitor
   kubectl logs -n health-monitor -l app=health-monitor --previous
   ```

2. **Redis connection issues:**
   ```bash
   kubectl exec -n health-monitor deployment/redis -- redis-cli ping
   ```

3. **NATS connectivity:**
   ```bash
   kubectl exec -n health-monitor deployment/nats -- nats-server --help
   ```

4. **CoRIM validation errors:**
   ```bash
   # Check application logs
   kubectl logs -n health-monitor deployment/health-monitor --tail=100
   
   # Validate CoRIM file locally
   curl -X POST http://localhost:8080/api/v1/corim/validate \
     -H "Content-Type: application/corim+cbor" \
     --data-binary @your-profile.cbor
   ```

### Performance Tuning

1. **Horizontal Pod Autoscaler**: Adjust CPU/memory thresholds
2. **Redis Memory**: Tune maxmemory-policy based on usage
3. **NATS JetStream**: Configure storage limits for persistence

### Backup and Recovery

1. **Redis backup:**
   ```bash
   kubectl exec -n health-monitor redis-0 -- redis-cli BGSAVE
   ```

2. **Configuration backup:**
   ```bash
   kubectl get configmap -n health-monitor -o yaml > config-backup.yaml
   ```

## 📈 Scaling Considerations

### Horizontal Scaling
- Health monitor: 3-10 replicas (HPA configured)
- Redis: Single instance with persistence (consider Redis Cluster for HA)
- NATS: 3-node cluster for high availability

### Resource Allocation
- **Health Monitor**: 256Mi-512Mi RAM, 250m-500m CPU
- **Redis**: 128Mi-256Mi RAM, 100m-250m CPU  
- **NATS**: 64Mi-128Mi RAM, 50m-100m CPU

### Storage Requirements
- Redis persistent volume: 10Gi (adjust based on CoRIM profile count)
- NATS JetStream: 1Gi (for message persistence)
- Application logs: Consider log rotation and external log aggregation

## 🔄 CI/CD Integration

The project includes GitHub Actions workflows for:
- Automated testing and security scanning
- Container image building and signing
- Staging and production deployments
- Rollback capabilities

Configure the following secrets in your GitHub repository:
- `KUBE_CONFIG_STAGING`: Base64-encoded kubeconfig for staging
- `KUBE_CONFIG_PRODUCTION`: Base64-encoded kubeconfig for production

## 🆘 Support and Maintenance

### Regular Maintenance Tasks
1. **Update dependencies**: Monthly Go module updates
2. **Security patches**: Weekly base image updates
3. **Certificate renewal**: Automated via cert-manager
4. **Backup verification**: Weekly backup testing

### Monitoring Alerts
Set up alerts for:
- Pod restarts > 5 in 10 minutes
- Memory usage > 80%
- CoRIM validation failures > 10/minute
- Redis/NATS connectivity issues

For additional support, check the project documentation or raise an issue in the repository.
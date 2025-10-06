# Health Monitor Production Operations Runbook

This runbook provides step-by-step procedures for operating the Distributed System Health Monitor with CoRIM integration in production environments.

## 📋 System Overview

The Health Monitor consists of:
- **Health Monitor Application**: Core service with CoRIM integration
- **Redis**: Caching and CoRIM profile storage
- **NATS**: Event streaming and messaging
- **Prometheus**: Metrics collection
- **Grafana**: Monitoring dashboards

## 🚨 Incident Response Procedures

### High Priority Incidents

#### 1. Service Unavailable (HTTP 5xx errors > 5%)

**Symptoms:**
- Health check endpoint returning 5xx errors
- High error rate in application logs
- Grafana dashboard showing service degradation

**Immediate Actions:**
1. Check pod status:
   ```bash
   kubectl get pods -n health-monitor -l app=health-monitor
   ```

2. Check recent deployments:
   ```bash
   kubectl rollout history deployment/health-monitor -n health-monitor
   ```

3. If recent deployment caused issues, rollback:
   ```bash
   kubectl rollout undo deployment/health-monitor -n health-monitor
   ```

4. Check resource utilization:
   ```bash
   kubectl top pods -n health-monitor
   ```

**Investigation Steps:**
1. Examine application logs:
   ```bash
   kubectl logs -n health-monitor -l app=health-monitor --tail=100
   ```

2. Check Redis connectivity:
   ```bash
   kubectl exec -n health-monitor deployment/health-monitor -- \
     redis-cli -h redis -p 6379 ping
   ```

3. Check NATS connectivity:
   ```bash
   kubectl exec -n health-monitor deployment/nats -- \
     nats-server --help > /dev/null && echo "NATS OK"
   ```

#### 2. Memory/CPU Resource Exhaustion

**Symptoms:**
- Pods being OOMKilled
- CPU throttling
- High resource utilization alerts

**Immediate Actions:**
1. Check HPA status:
   ```bash
   kubectl get hpa -n health-monitor
   ```

2. Scale horizontally if needed:
   ```bash
   kubectl scale deployment health-monitor --replicas=5 -n health-monitor
   ```

3. Check resource limits:
   ```bash
   kubectl describe deployment health-monitor -n health-monitor
   ```

#### 3. CoRIM Validation Failures Spike

**Symptoms:**
- High `corim_validation_failures_total` metric
- CoRIM upload endpoints returning 4xx errors
- Users reporting profile upload issues

**Investigation Steps:**
1. Check validation error logs:
   ```bash
   kubectl logs -n health-monitor -l app=health-monitor | grep "validation.*failed"
   ```

2. Examine recent CoRIM profiles:
   ```bash
   kubectl exec -n health-monitor deployment/health-monitor -- \
     redis-cli -h redis KEYS "corim:profile:*" | head -10
   ```

3. Test profile validation:
   ```bash
   # Use test CoRIM profile
   curl -X POST https://health-monitor.example.com/api/v1/corim/validate \
     -H "Content-Type: application/corim+cbor" \
     --data-binary @examples/sample_corim_profile.cbor
   ```

### Medium Priority Incidents

#### 1. Redis Connection Issues

**Symptoms:**
- Redis timeout errors in logs
- CoRIM profile operations failing
- `redis_connection_errors_total` metric increasing

**Actions:**
1. Check Redis pod health:
   ```bash
   kubectl get pods -n health-monitor -l app=redis
   kubectl logs -n health-monitor -l app=redis --tail=50
   ```

2. Test Redis connectivity:
   ```bash
   kubectl exec -n health-monitor redis-0 -- redis-cli ping
   ```

3. Check Redis memory usage:
   ```bash
   kubectl exec -n health-monitor redis-0 -- redis-cli info memory
   ```

4. If Redis is unhealthy, restart:
   ```bash
   kubectl delete pod -n health-monitor -l app=redis
   ```

#### 2. NATS Messaging Issues

**Symptoms:**
- Event processing delays
- NATS connection errors in logs
- Missing attestation events

**Actions:**
1. Check NATS cluster status:
   ```bash
   kubectl get pods -n health-monitor -l app=nats
   kubectl exec -n health-monitor nats-0 -- nats server check
   ```

2. Check message flow:
   ```bash
   kubectl exec -n health-monitor nats-0 -- nats stream ls
   ```

3. Restart NATS cluster if needed:
   ```bash
   kubectl rollout restart statefulset/nats -n health-monitor
   ```

## 📊 Monitoring and Alerting

### Key Metrics to Monitor

#### Application Metrics
- `http_requests_duration_seconds`: Request latency
- `http_requests_total`: Request volume and status codes
- `corim_profiles_total`: Total CoRIM profiles stored
- `corim_validation_duration_seconds`: Validation performance

#### Infrastructure Metrics
- CPU and memory utilization
- Pod restart count
- Network connectivity
- Persistent volume usage

### Alert Thresholds

#### Critical Alerts
- Service unavailable > 1 minute
- Error rate > 5% for 5 minutes
- Memory usage > 90% for 5 minutes
- Disk usage > 85%

#### Warning Alerts
- Response time > 2 seconds (95th percentile)
- Error rate > 1% for 10 minutes
- Pod restart > 3 times in 1 hour

### Grafana Dashboards

1. **Application Overview**: Service health, request rates, error rates
2. **CoRIM Metrics**: Profile counts, validation metrics, storage usage
3. **Infrastructure**: Pod status, resource utilization, network metrics
4. **Alerts**: Current and historical alert status

## 🔧 Maintenance Procedures

### Regular Maintenance Tasks

#### Daily
1. **Health Check Verification**:
   ```bash
   curl -f https://health-monitor.example.com/health
   ```

2. **Log Review**: Check for any ERROR or WARN level logs

3. **Metric Review**: Verify key metrics are within normal ranges

#### Weekly
1. **Backup Verification**:
   ```bash
   # Verify Redis backup
   kubectl exec -n health-monitor redis-0 -- redis-cli LASTSAVE
   ```

2. **Certificate Check**:
   ```bash
   kubectl get certificates -n health-monitor
   ```

3. **Resource Utilization Review**: Analyze trends and capacity planning

#### Monthly
1. **Dependency Updates**: Review and update Go modules
2. **Security Patch Review**: Update base container images
3. **Performance Review**: Analyze metrics and optimize if needed

### Scaling Operations

#### Horizontal Scaling
```bash
# Scale up during high load
kubectl scale deployment health-monitor --replicas=10 -n health-monitor

# Scale down during low usage
kubectl scale deployment health-monitor --replicas=3 -n health-monitor
```

#### Vertical Scaling
1. Update resource requests/limits in deployment manifest
2. Apply changes:
   ```bash
   kubectl apply -f deployments/k8s/health-monitor.yaml
   ```

### Configuration Updates

#### Application Configuration
1. Update ConfigMap:
   ```bash
   kubectl edit configmap health-monitor-config -n health-monitor
   ```

2. Restart pods to pick up changes:
   ```bash
   kubectl rollout restart deployment/health-monitor -n health-monitor
   ```

#### Redis Configuration
1. Update Redis configuration in StatefulSet
2. Perform rolling restart:
   ```bash
   kubectl rollout restart statefulset/redis -n health-monitor
   ```

## 🔍 Troubleshooting Guide

### Common Issues

#### 1. Pod CrashLoopBackOff
**Cause**: Application startup failure, misconfiguration
**Solution**:
```bash
kubectl describe pod <pod-name> -n health-monitor
kubectl logs <pod-name> -n health-monitor --previous
```

#### 2. ImagePullBackOff
**Cause**: Container image not accessible
**Solution**:
```bash
kubectl describe pod <pod-name> -n health-monitor
# Check image registry credentials and availability
```

#### 3. Service Discovery Issues
**Cause**: Network policies, DNS resolution
**Solution**:
```bash
kubectl exec -n health-monitor deployment/health-monitor -- nslookup redis
kubectl get networkpolicy -n health-monitor
```

#### 4. CoRIM Profile Corruption
**Cause**: Incomplete uploads, validation bypassed
**Solution**:
```bash
# List all profiles
kubectl exec -n health-monitor deployment/health-monitor -- \
  redis-cli -h redis KEYS "corim:profile:*"

# Remove corrupted profile
kubectl exec -n health-monitor deployment/health-monitor -- \
  redis-cli -h redis DEL "corim:profile:<profile-id>"
```

### Log Analysis

#### Important Log Patterns
- `ERROR`: Critical application errors requiring investigation
- `validation failed`: CoRIM profile validation issues
- `connection refused`: Network connectivity problems
- `context deadline exceeded`: Timeout issues

#### Log Aggregation Queries
```bash
# Recent errors
kubectl logs -n health-monitor -l app=health-monitor --since=1h | grep ERROR

# CoRIM validation issues
kubectl logs -n health-monitor -l app=health-monitor | grep "corim.*validation"

# Performance issues
kubectl logs -n health-monitor -l app=health-monitor | grep "slow.*request"
```

## 🚀 Deployment Procedures

### Production Deployment
1. **Pre-deployment checklist**:
   - [ ] All tests passing in CI/CD
   - [ ] Security scans completed
   - [ ] Deployment approved
   - [ ] Rollback plan ready

2. **Deployment steps**:
   ```bash
   # Using the deployment script
   ./scripts/deploy.sh production v1.2.0
   
   # Manual deployment
   kubectl set image deployment/health-monitor \
     health-monitor=health-monitor:v1.2.0 -n health-monitor
   ```

3. **Post-deployment verification**:
   ```bash
   # Check rollout status
   kubectl rollout status deployment/health-monitor -n health-monitor
   
   # Run smoke tests
   ./scripts/deploy.sh test production
   ```

### Rollback Procedure
```bash
# Automatic rollback (using script)
./scripts/deploy.sh rollback production

# Manual rollback
kubectl rollout undo deployment/health-monitor -n health-monitor
kubectl rollout status deployment/health-monitor -n health-monitor
```

## 📞 Emergency Contacts

### Escalation Matrix
- **Level 1**: On-call engineer (immediate response)
- **Level 2**: Platform team lead (within 30 minutes)
- **Level 3**: Architecture team (within 1 hour)

### Communication Channels
- **Slack**: #health-monitor-alerts
- **PagerDuty**: Health Monitor service
- **Email**: ops-team@company.com

### Service Dependencies
- **Redis**: Contact database team if cluster issues
- **NATS**: Contact messaging team for cluster problems
- **Kubernetes**: Contact platform team for cluster issues

## 📚 Additional Resources

- [Deployment Guide](DEPLOYMENT.md)
- [API Documentation](docs/api.md)
- [Architecture Overview](docs/architecture.md)
- [CoRIM Integration Guide](docs/corim.md)
- [Monitoring Setup](docs/monitoring.md)
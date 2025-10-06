#!/bin/bash
set -e

# Health Monitor Deployment Script
# This script automates the deployment process for different environments

ENVIRONMENT=${1:-"development"}
IMAGE_TAG=${2:-"latest"}
NAMESPACE="health-monitor"

echo "🚀 Starting deployment for environment: $ENVIRONMENT"
echo "📦 Using image tag: $IMAGE_TAG"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        print_error "docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Deploy based on environment
deploy_development() {
    print_status "Deploying to development environment with Docker Compose..."
    
    # Build the application
    print_status "Building application..."
    docker-compose build
    
    # Start services
    print_status "Starting services..."
    docker-compose up -d
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Health check
    if curl -f http://localhost:8080/health &> /dev/null; then
        print_success "Development deployment completed successfully"
        print_status "Services available at:"
        echo "  • Health Monitor: http://localhost:8080"
        echo "  • Grafana: http://localhost:3000 (admin/admin)"
        echo "  • Prometheus: http://localhost:9090"
    else
        print_error "Health check failed"
        docker-compose logs
        exit 1
    fi
}

deploy_kubernetes() {
    local env=$1
    print_status "Deploying to Kubernetes environment: $env"
    
    # Create namespace if it doesn't exist
    print_status "Creating namespace..."
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    
    # Update image tag in manifests
    print_status "Updating image tags..."
    local temp_dir=$(mktemp -d)
    cp -r deployments/k8s/* "$temp_dir/"
    
    # Replace image tag in manifests
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|health-monitor:latest|health-monitor:${IMAGE_TAG}|g" "$temp_dir/health-monitor.yaml"
    else
        # Linux
        sed -i "s|health-monitor:latest|health-monitor:${IMAGE_TAG}|g" "$temp_dir/health-monitor.yaml"
    fi
    
    # Deploy Redis
    print_status "Deploying Redis..."
    kubectl apply -f "$temp_dir/redis.yaml"
    
    # Deploy NATS
    print_status "Deploying NATS..."
    kubectl apply -f "$temp_dir/nats.yaml"
    
    # Wait for dependencies
    print_status "Waiting for Redis and NATS to be ready..."
    kubectl wait --for=condition=ready pod -l app=redis -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod -l app=nats -n $NAMESPACE --timeout=300s
    
    # Deploy health monitor
    print_status "Deploying health monitor application..."
    kubectl apply -f "$temp_dir/health-monitor.yaml"
    
    # Deploy ingress, HPA, PDB
    print_status "Deploying ingress and autoscaling..."
    kubectl apply -f "$temp_dir/ingress-hpa-pdb.yaml"
    
    # Wait for deployment to be ready
    print_status "Waiting for deployment to be ready..."
    kubectl rollout status deployment/health-monitor -n $NAMESPACE --timeout=600s
    
    # Clean up temp directory
    rm -rf "$temp_dir"
    
    # Health check
    print_status "Running health checks..."
    kubectl exec -n $NAMESPACE deployment/health-monitor -- curl -f http://localhost:8080/health
    
    print_success "Kubernetes deployment completed successfully"
    
    # Show deployment info
    print_status "Deployment information:"
    kubectl get pods -n $NAMESPACE -l app=health-monitor
    kubectl get svc -n $NAMESPACE
    
    # Get ingress info if available
    if kubectl get ingress -n $NAMESPACE health-monitor-ingress &> /dev/null; then
        print_status "Ingress configuration:"
        kubectl get ingress -n $NAMESPACE health-monitor-ingress
    fi
}

# Rollback function
rollback() {
    print_warning "Rolling back deployment..."
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        docker-compose down
        print_success "Development environment stopped"
    else
        kubectl rollout undo deployment/health-monitor -n $NAMESPACE
        kubectl rollout status deployment/health-monitor -n $NAMESPACE --timeout=300s
        print_success "Kubernetes deployment rolled back"
    fi
}

# Cleanup function
cleanup() {
    print_status "Cleaning up deployment..."
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        docker-compose down -v
        docker system prune -f
        print_success "Development environment cleaned up"
    else
        kubectl delete namespace $NAMESPACE --ignore-not-found=true
        print_success "Kubernetes resources cleaned up"
    fi
}

# Show logs
show_logs() {
    if [[ "$ENVIRONMENT" == "development" ]]; then
        docker-compose logs -f health-monitor
    else
        kubectl logs -n $NAMESPACE -l app=health-monitor -f --tail=100
    fi
}

# Monitor deployment
monitor() {
    print_status "Monitoring deployment status..."
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        docker-compose ps
        echo
        print_status "Health check:"
        curl -s http://localhost:8080/health | jq . || echo "Health endpoint not ready"
    else
        kubectl get pods -n $NAMESPACE -l app=health-monitor -w
    fi
}

# Test deployment
test_deployment() {
    print_status "Running deployment tests..."
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        # Test health endpoint
        if curl -f http://localhost:8080/health &> /dev/null; then
            print_success "Health endpoint test passed"
        else
            print_error "Health endpoint test failed"
            return 1
        fi
        
        # Test CoRIM endpoint
        if curl -f http://localhost:8080/api/v1/corim/profiles &> /dev/null; then
            print_success "CoRIM endpoint test passed"
        else
            print_error "CoRIM endpoint test failed"
            return 1
        fi
        
        # Test metrics endpoint
        if curl -f http://localhost:8081/metrics &> /dev/null; then
            print_success "Metrics endpoint test passed"
        else
            print_error "Metrics endpoint test failed"
            return 1
        fi
    else
        # Kubernetes tests
        kubectl exec -n $NAMESPACE deployment/health-monitor -- curl -f http://localhost:8080/health
        kubectl exec -n $NAMESPACE deployment/health-monitor -- curl -f http://localhost:8080/api/v1/corim/profiles
        kubectl exec -n $NAMESPACE deployment/health-monitor -- curl -f http://localhost:8081/metrics
        print_success "All Kubernetes tests passed"
    fi
}

# Main deployment logic
main() {
    case "$ENVIRONMENT" in
        "development"|"dev")
            deploy_development
            ;;
        "staging"|"stage")
            check_prerequisites
            deploy_kubernetes "staging"
            ;;
        "production"|"prod")
            check_prerequisites
            deploy_kubernetes "production"
            ;;
        *)
            print_error "Unknown environment: $ENVIRONMENT"
            echo "Usage: $0 {development|staging|production} [image_tag]"
            echo "Additional commands:"
            echo "  $0 rollback [environment]"
            echo "  $0 cleanup [environment]"
            echo "  $0 logs [environment]"
            echo "  $0 monitor [environment]"
            echo "  $0 test [environment]"
            exit 1
            ;;
    esac
}

# Handle additional commands
case "$1" in
    "rollback")
        ENVIRONMENT=${2:-"development"}
        rollback
        ;;
    "cleanup")
        ENVIRONMENT=${2:-"development"}
        cleanup
        ;;
    "logs")
        ENVIRONMENT=${2:-"development"}
        show_logs
        ;;
    "monitor")
        ENVIRONMENT=${2:-"development"}
        monitor
        ;;
    "test")
        ENVIRONMENT=${2:-"development"}
        test_deployment
        ;;
    *)
        check_prerequisites
        main
        ;;
esac
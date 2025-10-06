#!/bin/bash
set -e

echo "🚀 Cloud Deployment Guide for Health Monitor with CoRIM Integration"
echo "================================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_section() {
    echo -e "${BLUE}$1${NC}"
    echo "----------------------------------------"
}

print_step() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_section "📋 Available Deployment Options"

echo "1. 🚂 Railway.app (Recommended for demos)"
echo "   - Easy setup with database included"
echo "   - Free tier with custom domain"
echo "   - Automatic deployments from GitHub"
echo ""

echo "2. 🟣 Heroku"
echo "   - Classic PaaS with Redis addon"
echo "   - One-click deploy button"
echo "   - Custom domain on paid plans"
echo ""

echo "3. 🎨 Render.com"
echo "   - Modern platform with PostgreSQL/Redis"
echo "   - Free tier available"
echo "   - Automatic SSL certificates"
echo ""

echo "4. ☁️ Vercel/Netlify (Static + Serverless)"
echo "   - For frontend demos"
echo "   - Serverless API functions"
echo "   - Global CDN"
echo ""

print_section "🚂 Railway Deployment (Recommended)"

echo "Railway provides the easiest deployment for full-stack applications:"
echo ""
print_step "1. Push your code to GitHub"
print_step "2. Connect Railway to your GitHub repository"
print_step "3. Railway will automatically detect and deploy your Go application"
print_step "4. Add Redis database from Railway dashboard"
print_step "5. Get your live URL: https://your-app.railway.app"

echo ""
print_info "Railway Configuration:"
echo "   - Automatically uses railway.json for deployment settings"
echo "   - Includes Redis database addon"
echo "   - Environment variables auto-configured"
echo "   - Custom domain support"

print_section "🟣 Heroku Deployment"

echo "Deploy to Heroku with one-click:"
echo ""
print_step "1. Click the 'Deploy to Heroku' button (see README)"
print_step "2. Configure app name and region"
print_step "3. Heroku automatically provisions Redis addon"
print_step "4. Get your live URL: https://your-app.herokuapp.com"

echo ""
print_info "Heroku Features:"
echo "   - Uses app.json for configuration"
echo "   - Automatic Redis addon provisioning"
echo "   - Built-in logging with Papertrail"
echo "   - Easy scaling and monitoring"

print_section "🎨 Render Deployment"

echo "Deploy to Render.com:"
echo ""
print_step "1. Connect your GitHub repository to Render"
print_step "2. Render reads render.yaml configuration"
print_step "3. Automatically provisions Redis instance"
print_step "4. Get your live URL: https://your-app.onrender.com"

print_section "🔧 Pre-deployment Setup"

echo "Before deploying, ensure your repository has:"
echo ""
print_step "✓ All deployment configurations created"
print_step "✓ Environment variables documented"
print_step "✓ Health check endpoint implemented"
print_step "✓ CoRIM examples and documentation"

print_section "🌐 Getting Your Live Demo URL"

echo "After deployment, you'll have a live URL like:"
echo ""
echo "• https://health-monitor-demo.railway.app"
echo "• https://distributed-health-monitor.herokuapp.com"
echo "• https://health-monitor.onrender.com"
echo ""
echo "This URL can be added to your resume as a live project demo!"

print_section "📄 Resume Integration"

echo "Add to your resume:"
echo ""
echo "🔗 Live Demo: https://your-app.railway.app"
echo "📱 GitHub: https://github.com/Sukuna0007Abhi/Distributed-System-Health-Monitor"
echo ""
echo "Key features to highlight:"
echo "• Enterprise-grade health monitoring system"
echo "• CoRIM (Concise Reference Integrity Manifest) integration"
echo "• Real-time attestation validation"
echo "• Microservices architecture with Redis & NATS"
echo "• Production-ready with monitoring & observability"
echo "• RESTful API with comprehensive documentation"

print_section "🚀 Quick Deploy Commands"

echo "Choose your preferred platform:"
echo ""
echo "Railway:"
echo "  1. Push to GitHub"
echo "  2. Visit railway.app and connect repository"
echo "  3. Deploy automatically"
echo ""
echo "Heroku:"
echo "  heroku create your-health-monitor"
echo "  heroku addons:create heroku-redis:mini"
echo "  git push heroku main"
echo ""
echo "Render:"
echo "  1. Connect GitHub repository to Render"
echo "  2. Render auto-deploys using render.yaml"
echo ""

print_section "✅ Verification Steps"

echo "After deployment, verify your live demo:"
echo ""
echo "1. Health Check:"
echo "   curl https://your-app.railway.app/health"
echo ""
echo "2. CoRIM API:"
echo "   curl https://your-app.railway.app/api/v1/corim/profiles"
echo ""
echo "3. Metrics:"
echo "   curl https://your-app.railway.app/metrics"

echo ""
echo "🎉 Your Health Monitor with CoRIM integration is now ready for live deployment!"
echo "   Add the live URL to your resume to showcase your work to potential employers."
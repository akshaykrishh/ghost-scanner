#!/bin/bash

# Ghost Scanner Setup Script
# This script sets up the Ghost Scanner MVP environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    log_step "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_info "Docker and Docker Compose are installed"
}

# Check if required tools are installed
check_tools() {
    log_step "Checking required tools..."
    
    local missing_tools=()
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if ! command -v pip3 &> /dev/null; then
        missing_tools+=("pip3")
    fi
    
    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and run this script again."
        exit 1
    fi
    
    log_info "All required tools are installed"
}

# Setup environment file
setup_env() {
    log_step "Setting up environment configuration..."
    
    if [ ! -f ".env" ]; then
        if [ -f "env.example" ]; then
            cp env.example .env
            log_info "Created .env file from env.example"
            log_warn "Please update the .env file with your actual configuration values"
        else
            log_error "env.example file not found"
            exit 1
        fi
    else
        log_info ".env file already exists"
    fi
}

# Install Python dependencies
install_python_deps() {
    log_step "Installing Python dependencies..."
    
    if [ -f "backend/requirements.txt" ]; then
        cd backend
        pip3 install -r requirements.txt
        cd ..
        log_info "Python dependencies installed"
    else
        log_error "backend/requirements.txt not found"
        exit 1
    fi
}

# Setup database
setup_database() {
    log_step "Setting up database..."
    
    # Start PostgreSQL and Redis using Docker Compose
    docker-compose up -d postgres redis
    
    # Wait for services to be ready
    log_info "Waiting for database services to be ready..."
    sleep 10
    
    # Run database migrations (if Alembic is configured)
    if [ -f "backend/alembic.ini" ]; then
        cd backend
        alembic upgrade head
        cd ..
        log_info "Database migrations completed"
    else
        log_warn "Alembic configuration not found, skipping migrations"
    fi
}

# Build Docker images
build_images() {
    log_step "Building Docker images..."
    
    docker-compose build
    log_info "Docker images built successfully"
}

# Start services
start_services() {
    log_step "Starting Ghost Scanner services..."
    
    docker-compose up -d
    log_info "All services started"
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 15
    
    # Check service health
    check_service_health
}

# Check service health
check_service_health() {
    log_step "Checking service health..."
    
    # Check backend health
    if curl -f http://localhost:8000/health &> /dev/null; then
        log_info "Backend service is healthy"
    else
        log_warn "Backend service health check failed"
    fi
    
    # Check database connection
    if docker-compose exec postgres pg_isready -U ghost_scanner &> /dev/null; then
        log_info "PostgreSQL is healthy"
    else
        log_warn "PostgreSQL health check failed"
    fi
    
    # Check Redis connection
    if docker-compose exec redis redis-cli ping &> /dev/null; then
        log_info "Redis is healthy"
    else
        log_warn "Redis health check failed"
    fi
}

# Display setup completion information
display_completion() {
    log_step "Setup completed!"
    
    echo ""
    echo -e "${GREEN}🎉 Ghost Scanner MVP is now running!${NC}"
    echo ""
    echo "Services:"
    echo "  • Backend API: http://localhost:8000"
    echo "  • API Documentation: http://localhost:8000/docs"
    echo "  • PostgreSQL: localhost:5432"
    echo "  • Redis: localhost:6379"
    echo ""
    echo "Next steps:"
    echo "  1. Update the .env file with your actual configuration"
    echo "  2. Set up your OpenAI API key for AI features"
    echo "  3. Configure GitHub integration"
    echo "  4. Test the API endpoints"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart services: docker-compose restart"
    echo ""
}

# Main setup function
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Ghost Scanner MVP Setup                  ║"
    echo "║              AI-Enhanced CI/CD Security Platform           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_docker
    check_tools
    setup_env
    install_python_deps
    setup_database
    build_images
    start_services
    display_completion
}

# Run main function
main "$@"

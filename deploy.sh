#!/bin/bash

# PDF Scrubber Deployment Script
# Production deployment automation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DEPLOYMENT_ENV=${DEPLOYMENT_ENV:-production}
DEPLOY_USER=${DEPLOY_USER:-pdfscrubber}
DEPLOY_PATH=${DEPLOY_PATH:-/opt/pdfscrubber}
SERVICE_NAME=${SERVICE_NAME:-pdfscrubber}
BACKUP_RETENTION=${BACKUP_RETENTION:-7}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
pre_deployment_checks() {
    print_status "Running pre-deployment checks..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root - consider using a dedicated user"
    fi
    
    # Check disk space
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 1048576 ]]; then  # 1GB in KB
        print_error "Insufficient disk space (less than 1GB available)"
        exit 1
    fi
    
    # Check system resources
    MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ $MEMORY_KB -lt 1048576 ]]; then  # 1GB in KB
        print_warning "Low memory system detected (less than 1GB)"
    fi
    
    # Verify build artifacts
    if [[ ! -f "build/bin/pdfscrubber" ]]; then
        print_error "Build artifacts not found - run build.sh first"
        exit 1
    fi
    
    print_status "Pre-deployment checks passed"
}

# Create deployment user and directories
setup_deployment_environment() {
    print_status "Setting up deployment environment..."
    
    # Create user if doesn't exist
    if ! id "$DEPLOY_USER" &>/dev/null; then
        sudo useradd -r -m -s /bin/bash "$DEPLOY_USER"
        print_status "Created user: $DEPLOY_USER"
    fi
    
    # Create directories
    sudo mkdir -p "$DEPLOY_PATH"/{bin,config,data,logs,backups}
    sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH"
    sudo chmod 755 "$DEPLOY_PATH"
    
    # Create config directory structure
    sudo -u "$DEPLOY_USER" mkdir -p "$DEPLOY_PATH"/config/{scrubber,forensic,profiles}
    sudo -u "$DEPLOY_USER" mkdir -p "$DEPLOY_PATH"/data/{input,output,temp}
    sudo -u "$DEPLOY_USER" mkdir -p "$DEPLOY_PATH"/logs/{scrubber,forensic,system}
    
    print_status "Deployment environment ready"
}

# Backup existing deployment
backup_existing_deployment() {
    if [[ -d "$DEPLOY_PATH/bin" ]]; then
        print_status "Backing up existing deployment..."
        
        BACKUP_NAME="pdfscrubber-backup-$(date +%Y%m%d-%H%M%S)"
        sudo -u "$DEPLOY_USER" mkdir -p "$DEPLOY_PATH/backups/$BACKUP_NAME"
        
        # Backup binaries and config
        sudo -u "$DEPLOY_USER" cp -r "$DEPLOY_PATH/bin" "$DEPLOY_PATH/backups/$BACKUP_NAME/"
        sudo -u "$DEPLOY_USER" cp -r "$DEPLOY_PATH/config" "$DEPLOY_PATH/backups/$BACKUP_NAME/" 2>/dev/null || true
        
        print_status "Backup created: $BACKUP_NAME"
        
        # Clean old backups
        sudo -u "$DEPLOY_USER" find "$DEPLOY_PATH/backups" -maxdepth 1 -type d -mtime +$BACKUP_RETENTION -exec rm -rf {} \; 2>/dev/null || true
    fi
}

# Deploy application
deploy_application() {
    print_status "Deploying application..."
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Stopping $SERVICE_NAME service..."
        sudo systemctl stop "$SERVICE_NAME"
    fi
    
    # Copy binaries
    sudo cp build/bin/* "$DEPLOY_PATH/bin/"
    sudo chown "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH/bin"/*
    sudo chmod 755 "$DEPLOY_PATH/bin"/*
    
    # Copy documentation
    sudo cp *.md "$DEPLOY_PATH/" 2>/dev/null || true
    sudo chown "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH"/*.md 2>/dev/null || true
    
    print_status "Application deployed"
}

# Configure systemd service
configure_service() {
    print_status "Configuring systemd service..."
    
    # Create service file
    sudo tee /etc/systemd/system/"$SERVICE_NAME".service > /dev/null <<EOF
[Unit]
Description=PDF Scrubber Service
After=network.target
Wants=network.target

[Service]
Type=notify
User=$DEPLOY_USER
Group=$DEPLOY_USER
WorkingDirectory=$DEPLOY_PATH
ExecStart=$DEPLOY_PATH/bin/pdfscrubber --daemon --config=$DEPLOY_PATH/config/scrubber.conf
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DEPLOY_PATH/data $DEPLOY_PATH/logs $DEPLOY_PATH/config
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=2G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    
    print_status "Service configured"
}

# Create default configuration
create_default_config() {
    print_status "Creating default configuration..."
    
    # Main scrubber configuration
    sudo -u "$DEPLOY_USER" tee "$DEPLOY_PATH/config/scrubber.conf" > /dev/null <<EOF
# PDF Scrubber Configuration
# Environment: $DEPLOYMENT_ENV

[scrubber]
max_file_size = 100MB
max_objects = 100000
max_recursion_depth = 50
max_string_length = 1MB
max_stream_size = 50MB
max_parse_time = 30s
strict_validation = true
enable_recovery = true

[logging]
level = info
file = $DEPLOY_PATH/logs/scrubber/scrubber.log
max_size = 100MB
max_files = 10
console = false

[security]
enable_sandbox = true
restrict_file_access = true
deny_network = true
memory_limit = 2GB
cpu_limit = 200%

[performance]
enable_caching = true
cache_size = 100MB
parallel_processing = true
max_threads = 4

[forensic]
enable_metadata_extraction = true
enable_signature_analysis = true
enable_hidden_content_detection = true
enable_vulnerability_scanning = true
EOF

    # Forensic configuration
    sudo -u "$DEPLOY_USER" tee "$DEPLOY_PATH/config/forensic.conf" > /dev/null <<EOF
# PDF Forensic Analysis Configuration

[analysis]
deep_inspection = true
extract_javascript = true
extract_forms = true
extract_embedded_files = true
analyze_creation_tools = true
detect_anomalies = true

[reporting]
output_format = json
include_raw_data = false
verbose_logging = true
generate_hashes = true

[performance]
timeout = 300s
memory_limit = 1GB
EOF

    sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH/config"
    print_status "Default configuration created"
}

# Configure logging
configure_logging() {
    print_status "Configuring logging..."
    
    # Create logrotate configuration
    sudo tee /etc/logrotate.d/pdfscrubber > /dev/null <<EOF
$DEPLOY_PATH/logs/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $DEPLOY_USER $DEPLOY_USER
    postrotate
        /bin/systemctl reload $SERVICE_NAME 2>/dev/null || true
    endscript
}
EOF

    print_status "Logging configured"
}

# Start services
start_services() {
    print_status "Starting services..."
    
    # Start and verify service
    sudo systemctl start "$SERVICE_NAME"
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service started successfully"
    else
        print_error "Service failed to start"
        sudo systemctl status "$SERVICE_NAME"
        exit 1
    fi
}

# Post-deployment verification
post_deployment_verification() {
    print_status "Running post-deployment verification..."
    
    # Test binaries
    if ! sudo -u "$DEPLOY_USER" "$DEPLOY_PATH/bin/pdfscrubber" --version >/dev/null 2>&1; then
        print_error "Main binary test failed"
        exit 1
    fi
    
    if ! sudo -u "$DEPLOY_USER" "$DEPLOY_PATH/bin/pdfforensic" --version >/dev/null 2>&1; then
        print_error "Forensic binary test failed"
        exit 1
    fi
    
    # Test configuration
    if [[ ! -f "$DEPLOY_PATH/config/scrubber.conf" ]]; then
        print_error "Configuration file missing"
        exit 1
    fi
    
    # Test permissions
    if [[ ! -w "$DEPLOY_PATH/data" ]]; then
        print_error "Data directory not writable"
        exit 1
    fi
    
    print_status "Post-deployment verification passed"
}

# Rollback function
rollback_deployment() {
    print_status "Rolling back deployment..."
    
    # Find latest backup
    LATEST_BACKUP=$(sudo -u "$DEPLOY_USER" find "$DEPLOY_PATH/backups" -maxdepth 1 -type d -name "pdfscrubber-backup-*" | sort | tail -1)
    
    if [[ -z "$LATEST_BACKUP" ]]; then
        print_error "No backup found for rollback"
        exit 1
    fi
    
    print_status "Rolling back to: $(basename "$LATEST_BACKUP")"
    
    # Stop service
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    
    # Restore from backup
    sudo rm -rf "$DEPLOY_PATH/bin"
    sudo -u "$DEPLOY_USER" cp -r "$LATEST_BACKUP/bin" "$DEPLOY_PATH/"
    sudo -u "$DEPLOY_USER" cp -r "$LATEST_BACKUP/config"/* "$DEPLOY_PATH/config/" 2>/dev/null || true
    
    # Start service
    sudo systemctl start "$SERVICE_NAME"
    
    print_status "Rollback completed"
}

# Main deployment function
main() {
    case "${1:-deploy}" in
        "deploy")
            print_status "Starting deployment process..."
            pre_deployment_checks
            setup_deployment_environment
            backup_existing_deployment
            deploy_application
            configure_service
            create_default_config
            configure_logging
            start_services
            post_deployment_verification
            print_status "Deployment completed successfully!"
            echo ""
            echo -e "${GREEN}Deployment Summary:${NC}"
            echo "  - Service: $SERVICE_NAME"
            echo "  - Path: $DEPLOY_PATH"
            echo "  - User: $DEPLOY_USER"
            echo "  - Environment: $DEPLOYMENT_ENV"
            echo ""
            echo -e "${GREEN}Service Commands:${NC}"
            echo "  - Status: sudo systemctl status $SERVICE_NAME"
            echo "  - Logs: sudo journalctl -u $SERVICE_NAME -f"
            echo "  - Restart: sudo systemctl restart $SERVICE_NAME"
            ;;
        "rollback")
            rollback_deployment
            ;;
        "status")
            systemctl status "$SERVICE_NAME"
            ;;
        "logs")
            journalctl -u "$SERVICE_NAME" -f
            ;;
        *)
            echo "Usage: $0 [deploy|rollback|status|logs]"
            exit 1
            ;;
    esac
}

# Show help
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "PDF Scrubber Deployment Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  deploy    - Full deployment (default)"
    echo "  rollback  - Rollback to previous version"
    echo "  status    - Show service status"
    echo "  logs      - Show service logs"
    echo ""
    echo "Environment variables:"
    echo "  DEPLOYMENT_ENV    - Deployment environment (default: production)"
    echo "  DEPLOY_USER       - Deployment user (default: pdfscrubber)"
    echo "  DEPLOY_PATH       - Deployment path (default: /opt/pdfscrubber)"
    echo "  SERVICE_NAME      - Service name (default: pdfscrubber)"
    echo "  BACKUP_RETENTION  - Backup retention days (default: 7)"
    exit 0
fi

main "$@"
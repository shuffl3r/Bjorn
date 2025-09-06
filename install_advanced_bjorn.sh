#!/bin/bash

# install_advanced_bjorn.sh
# Installation script for Advanced Bjorn capabilities
# Adds AI-driven targeting, high-speed scanning, and advanced vulnerability assessment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check if we're in the Bjorn directory
check_bjorn_directory() {
    if [[ ! -f "Bjorn.py" ]] || [[ ! -d "actions" ]]; then
        error "This script must be run from the Bjorn root directory"
        error "Please navigate to your Bjorn installation directory and run this script again"
        exit 1
    fi
    log "Bjorn directory detected"
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Run dependency checker if available
    if [[ -f "check_dependencies.py" ]]; then
        info "Running comprehensive dependency check..."
        if python3 check_dependencies.py; then
            log "Dependency check passed"
        else
            warn "Dependency check found issues. Please review and resolve them."
            read -p "Do you want to continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Installation cancelled. Please resolve dependency issues first."
                exit 1
            fi
        fi
    fi
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not installed"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$python_version >= 3.7" | bc -l) -eq 0 ]]; then
        error "Python 3.7 or higher is required. Current version: $python_version"
        exit 1
    fi
    log "Python $python_version detected"
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is required but not installed"
        exit 1
    fi
    
    # Check available disk space (need at least 500MB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [[ $available_space -lt 512000 ]]; then
        warn "Low disk space detected. At least 500MB recommended"
    fi
    
    log "System requirements check passed"
}

# Install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    sudo apt-get update -qq
    
    # Install required packages
    packages=(
        "masscan"
        "nmap"
        "searchsploit"
        "python3-dev"
        "python3-pip"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "libxml2-dev"
        "libxslt1-dev"
        "zlib1g-dev"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            info "Installing $package..."
            sudo apt-get install -y "$package" || warn "Failed to install $package"
        else
            info "$package is already installed"
        fi
    done
    
    # Update Exploit-DB if searchsploit is available
    if command -v searchsploit &> /dev/null; then
        info "Updating Exploit-DB database..."
        sudo searchsploit -u || warn "Failed to update Exploit-DB"
    fi
    
    log "System dependencies installation completed"
}

# Install Python dependencies
install_python_dependencies() {
    log "Installing Python dependencies..."
    
    # Create requirements file for advanced features
    cat > requirements_advanced.txt << EOF
# Advanced Bjorn Requirements
requests>=2.25.0
numpy>=1.19.0
dataclasses>=0.6; python_version<"3.7"
typing-extensions>=3.7.4
lxml>=4.6.0
python-nmap>=0.6.1
xmltodict>=0.12.0
beautifulsoup4>=4.9.0
urllib3>=1.26.0
certifi>=2020.12.5
charset-normalizer>=2.0.0
idna>=2.10
EOF
    
    # Install Python packages
    info "Installing Python packages..."
    pip3 install --user -r requirements_advanced.txt
    
    # Also install from existing requirements if it exists
    if [[ -f "requirements.txt" ]]; then
        info "Installing existing Bjorn requirements..."
        pip3 install --user -r requirements.txt
    fi
    
    log "Python dependencies installation completed"
}

# Backup existing configuration
backup_configuration() {
    log "Creating backup of existing configuration..."
    
    backup_dir="backup/advanced_upgrade_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup important files
    files_to_backup=(
        "config/shared_config.json"
        "orchestrator.py"
        "Bjorn.py"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            cp "$file" "$backup_dir/"
            info "Backed up $file"
        fi
    done
    
    log "Backup created in $backup_dir"
    echo "$backup_dir" > .last_backup_location
}

# Install advanced modules
install_advanced_modules() {
    log "Installing advanced modules..."
    
    # Check if advanced modules already exist
    advanced_modules=(
        "actions/masscan_scanner.py"
        "actions/advanced_vuln_scanner.py"
        "actions/intelligent_targeting.py"
    )
    
    for module in "${advanced_modules[@]}"; do
        if [[ -f "$module" ]]; then
            info "Advanced module $module already exists"
        else
            error "Advanced module $module not found. Please ensure all files are present."
            exit 1
        fi
    done
    
    # Check configuration files
    config_files=(
        "config/advanced_actions.json"
        "enhanced_orchestrator.py"
    )
    
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            info "Configuration file $config found"
        else
            error "Configuration file $config not found. Please ensure all files are present."
            exit 1
        fi
    done
    
    log "Advanced modules verification completed"
}

# Configure Masscan
configure_masscan() {
    log "Configuring Masscan..."
    
    # Check if masscan is installed and accessible
    if ! command -v masscan &> /dev/null; then
        error "Masscan is not installed or not in PATH"
        exit 1
    fi
    
    # Test masscan permissions
    if ! masscan --version &> /dev/null; then
        warn "Masscan may require additional permissions"
        info "You may need to run: sudo setcap cap_net_raw+ep \$(which masscan)"
    fi
    
    # Create masscan configuration directory
    mkdir -p data/output/scan_results
    mkdir -p data/output/vulnerabilities
    mkdir -p data/output/targeting
    
    log "Masscan configuration completed"
}

# Update shared configuration
update_shared_config() {
    log "Updating shared configuration..."
    
    # The shared_config.json should already be updated with advanced settings
    if grep -q "use_masscan" config/shared_config.json; then
        info "Advanced configuration already present in shared_config.json"
    else
        warn "Advanced configuration not found in shared_config.json"
        warn "Please manually update the configuration file"
    fi
    
    log "Configuration update completed"
}

# Create startup script for enhanced Bjorn
create_startup_script() {
    log "Creating enhanced startup script..."
    
    cat > start_enhanced_bjorn.py << 'EOF'
#!/usr/bin/env python3
"""
Enhanced Bjorn Startup Script
Starts Bjorn with advanced AI-driven capabilities
"""

import sys
import os
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from enhanced_orchestrator import EnhancedOrchestrator
    from init_shared import shared_data
    from display import Display, handle_exit_display
    from webapp import web_thread
    from logger import Logger
    import threading
    import signal
    
    logger = Logger(name="start_enhanced_bjorn", level=logging.INFO)
    
    def handle_exit(sig, frame, display_thread, bjorn_thread, web_thread):
        """Handle clean exit"""
        shared_data.should_exit = True
        shared_data.orchestrator_should_exit = True
        shared_data.display_should_exit = True
        shared_data.webapp_should_exit = True
        
        logger.info("Shutting down Enhanced Bjorn...")
        
        if display_thread and display_thread.is_alive():
            display_thread.join(timeout=5)
        if bjorn_thread and bjorn_thread.is_alive():
            bjorn_thread.join(timeout=5)
        if web_thread and web_thread.is_alive():
            web_thread.join(timeout=5)
            
        logger.info("Enhanced Bjorn shutdown complete")
        sys.exit(0)
    
    def main():
        logger.info("Starting Enhanced Bjorn with AI capabilities...")
        
        try:
            # Load configuration
            shared_data.load_config()
            
            # Start display thread
            shared_data.display_should_exit = False
            display = Display(shared_data)
            display_thread = threading.Thread(target=display.run)
            display_thread.start()
            
            # Start enhanced orchestrator
            orchestrator = EnhancedOrchestrator()
            bjorn_thread = threading.Thread(target=orchestrator.run)
            bjorn_thread.start()
            
            # Start web server if enabled
            web_thread_obj = None
            if shared_data.config.get("websrv", False):
                logger.info("Starting web server...")
                web_thread_obj = web_thread
                web_thread_obj.start()
            
            # Set up signal handlers
            signal.signal(signal.SIGINT, 
                         lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread_obj))
            signal.signal(signal.SIGTERM, 
                         lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread_obj))
            
            logger.info("Enhanced Bjorn started successfully!")
            logger.info("Advanced features enabled:")
            if shared_data.config.get('use_masscan', False):
                logger.info("  - High-speed Masscan scanning")
            if shared_data.config.get('use_advanced_vuln_scanner', False):
                logger.info("  - Advanced vulnerability assessment with CVE database")
            if shared_data.config.get('use_intelligent_targeting', False):
                logger.info("  - AI-driven intelligent targeting")
            
            # Keep main thread alive
            while not shared_data.should_exit:
                import time
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Error starting Enhanced Bjorn: {e}")
            sys.exit(1)
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure all dependencies are installed")
    sys.exit(1)
EOF
    
    chmod +x start_enhanced_bjorn.py
    log "Enhanced startup script created: start_enhanced_bjorn.py"
}

# Create systemd service (optional)
create_systemd_service() {
    if [[ "$1" == "yes" ]]; then
        log "Creating systemd service..."
        
        current_dir=$(pwd)
        current_user=$(whoami)
        
        sudo tee /etc/systemd/system/enhanced-bjorn.service > /dev/null << EOF
[Unit]
Description=Enhanced Bjorn - AI-Driven Network Security Tool
After=network.target
Wants=network.target

[Service]
Type=simple
User=$current_user
Group=$current_user
WorkingDirectory=$current_dir
ExecStart=/usr/bin/python3 $current_dir/start_enhanced_bjorn.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable enhanced-bjorn.service
        
        log "Systemd service created and enabled"
        info "Use 'sudo systemctl start enhanced-bjorn' to start the service"
        info "Use 'sudo systemctl status enhanced-bjorn' to check status"
    fi
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Check if Python can import the modules
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from actions.masscan_scanner import MasscanScanner
    from actions.advanced_vuln_scanner import AdvancedVulnScanner
    from actions.intelligent_targeting import IntelligentTargeting
    from enhanced_orchestrator import EnhancedOrchestrator
    print('✓ All advanced modules can be imported successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
" || {
        error "Module import verification failed"
        exit 1
    }
    
    # Check configuration
    if [[ -f "config/shared_config.json" ]] && [[ -f "config/advanced_actions.json" ]]; then
        info "✓ Configuration files present"
    else
        error "✗ Configuration files missing"
        exit 1
    fi
    
    # Check required directories
    required_dirs=(
        "data/output/scan_results"
        "data/output/vulnerabilities"
        "data/output/targeting"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            info "✓ Directory $dir exists"
        else
            warn "✗ Directory $dir missing, creating..."
            mkdir -p "$dir"
        fi
    done
    
    log "Installation verification completed successfully!"
}

# Display post-installation information
show_post_install_info() {
    log "Installation completed successfully!"
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Enhanced Bjorn Installed                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}New Advanced Features:${NC}"
    echo -e "  ${GREEN}•${NC} High-speed Masscan scanning (1000x faster)"
    echo -e "  ${GREEN}•${NC} Advanced vulnerability assessment with real-time CVE database"
    echo -e "  ${GREEN}•${NC} AI-driven intelligent targeting and attack prioritization"
    echo -e "  ${GREEN}•${NC} EPSS exploit prediction scoring"
    echo -e "  ${GREEN}•${NC} Automated exploit availability checking"
    echo
    echo -e "${BLUE}How to start Enhanced Bjorn:${NC}"
    echo -e "  ${YELLOW}./start_enhanced_bjorn.py${NC}  (Recommended - with all advanced features)"
    echo -e "  ${YELLOW}python3 Bjorn.py${NC}          (Standard mode - original functionality)"
    echo
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  Edit ${YELLOW}config/shared_config.json${NC} to enable/disable advanced features"
    echo -e "  Advanced settings are in the ${YELLOW}__title_advanced__${NC} section"
    echo
    echo -e "${BLUE}Optional API Keys (for enhanced functionality):${NC}"
    echo -e "  ${YELLOW}nvd_api_key${NC}: Get from https://nvd.nist.gov/developers/request-an-api-key"
    echo -e "  This enables faster CVE database queries (recommended for production use)"
    echo
    echo -e "${BLUE}Monitoring:${NC}"
    echo -e "  Web interface: ${YELLOW}http://localhost:8000${NC} (if web server enabled)"
    echo -e "  Logs: Check terminal output and log files in data/output/"
    echo
    if [[ -f ".last_backup_location" ]]; then
        backup_location=$(cat .last_backup_location)
        echo -e "${BLUE}Backup:${NC}"
        echo -e "  Your original configuration was backed up to: ${YELLOW}$backup_location${NC}"
        echo
    fi
    echo -e "${GREEN}Enhanced Bjorn is ready to hunt! 🏹${NC}"
    echo
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Enhanced Bjorn Installation Script             ║"
    echo "║                                                              ║"
    echo "║  This script will install advanced AI-driven capabilities   ║"
    echo "║  including high-speed scanning and intelligent targeting     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    
    # Confirmation prompt
    read -p "Do you want to proceed with the installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Installation cancelled by user"
        exit 0
    fi
    
    # Ask about systemd service
    read -p "Do you want to create a systemd service for auto-start? (y/N): " -n 1 -r
    echo
    create_service="no"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_service="yes"
    fi
    
    # Run installation steps
    check_root
    check_bjorn_directory
    check_requirements
    install_system_dependencies
    install_python_dependencies
    backup_configuration
    install_advanced_modules
    configure_masscan
    update_shared_config
    create_startup_script
    create_systemd_service "$create_service"
    verify_installation
    show_post_install_info
}

# Run main function
main "$@"

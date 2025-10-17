#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Decoy machine configuration
DECOY_PRIVATE_IP="10.0.2.48"
DECOY_PUBLIC_IP="141.253.108.153"

# Change to the project directory
cd "$(dirname "$0")/.."

echo -e "${BLUE}=== CTI Multi-Protocol Honeypot Deployment ===${NC}"
echo "Current directory: $(pwd)"
echo "Current user: $(whoami)"
echo "Timestamp: $(date)"
echo "Target decoy machine (private): ${DECOY_PRIVATE_IP}"
echo "Target decoy machine (public): ${DECOY_PUBLIC_IP}"

# Function to print colored messages
print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Validation functions
validate_requirements() {
    print_status "Validating requirements..."
    
    # Check if ansible is installed
    if ! command -v ansible &> /dev/null; then
        print_error "Ansible is not installed"
        exit 1
    fi
    
    # Check inventory file
    if [ ! -f "ansible/inventory/hosts.ini" ]; then
        print_error "Inventory file not found at ansible/inventory/hosts.ini"
        exit 1
    fi
    
    # Check playbook
    if [ ! -f "ansible/playbooks/deploy_ssh_honeypot.yml" ]; then
        print_error "Playbook not found at ansible/playbooks/deploy_ssh_honeypot.yml"
        exit 1
    fi
    
    # Check SSH & Telnet honeypot files
    if [ ! -f "../Honeypots/ssh & telnet/docker-compose.yml" ]; then
        print_error "SSH & Telnet docker-compose.yml not found in ../Honeypots/ssh & telnet/"
        exit 1
    fi
    
    if [ ! -f "../Honeypots/ssh & telnet/init-config.sh" ]; then
        print_error "SSH & Telnet init-config.sh not found in ../Honeypots/ssh & telnet/"
        exit 1
    fi
    
    # Check HTTP honeypot files
    if [ ! -f "../Honeypots/http/docker-compose.yml" ]; then
        print_error "HTTP docker-compose.yml not found in ../Honeypots/http/"
        exit 1
    fi
    
    if [ ! -f "../Honeypots/http/nginx.conf" ]; then
        print_error "HTTP nginx.conf not found in ../Honeypots/http/"
        exit 1
    fi
    
    if [ ! -f "../Honeypots/http/default.conf" ]; then
        print_error "HTTP default.conf not found in ../Honeypots/http/"
        exit 1
    fi
    
    # Check if ansible collections are available
    if ! ansible-galaxy collection list | grep -q community.docker; then
        print_status "Installing community.docker collection..."
        ansible-galaxy collection install community.docker --force
    fi
    
    print_status "All honeypot files validated successfully"
}

# Test connectivity
test_connectivity() {
    print_status "Testing connectivity to Ubuntu 22.04 target hosts..."
    if ansible all -i "ansible/inventory/hosts.ini" -m ping --timeout=30; then
        print_status "Connectivity test passed"
    else
        print_error "Connectivity test failed - check SSH keys and network connectivity"
        exit 1
    fi
}

# Pre-deployment checks
pre_deployment_checks() {
    print_status "Running pre-deployment checks..."
    
    # Check Ubuntu version and system info
    print_status "Checking target system information..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m setup \
        -a "filter=ansible_distribution*,ansible_memtotal_mb,ansible_processor_count" \
        --become || exit 1
    
    # Check Docker status
    print_status "Verifying Docker installation..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m systemd \
        -a "name=docker" --become || exit 1
    
    # Check Docker Compose
    print_status "Verifying Docker Compose availability..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "docker compose version" --become || exit 1
    
    # Check available disk space
    print_status "Checking available disk space..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "df -h /" --become
    
    print_status "Pre-deployment checks completed successfully"
}

# Deploy honeypots
deploy_honeypots() {
    print_status "Deploying multi-protocol honeypots (SSH/Telnet/HTTP)..."
    
    # Create logs directory
    mkdir -p logs
    
    # Run the deployment playbook
    if ansible-playbook -i "ansible/inventory/hosts.ini" "ansible/playbooks/deploy_ssh_honeypot.yml" -v; then
        print_status "Multi-protocol honeypot deployment completed successfully"
    else
        print_error "Deployment failed - check the playbook output above"
        exit 1
    fi
}

# Post-deployment verification
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Wait for containers to fully start
    print_status "Waiting for containers to initialize..."
    sleep 10
    
    # Check if SSH/Telnet containers are running
    print_status "Checking SSH/Telnet containers..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /opt/honeypot/config && docker compose -f ssh-telnet-compose.yml ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'" \
        --become-user=ubuntu || print_warning "SSH/Telnet containers check failed"
    
    # Check if HTTP containers are running
    print_status "Checking HTTP containers..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /opt/honeypot/config && docker compose -f http-compose.yml ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'" \
        --become-user=ubuntu || print_warning "HTTP containers check failed"
    
    # Check Docker logs for errors
    print_status "Checking for container errors..."
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /opt/honeypot/config && docker compose -f ssh-telnet-compose.yml logs --tail=5" \
        --become-user=ubuntu || true
    
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /opt/honeypot/config && docker compose -f http-compose.yml logs --tail=5" \
        --become-user=ubuntu || true
    
    print_status "Deployment verification completed"
}

# Test honeypot connectivity (use public IP for external testing)
test_honeypot_ports() {
    print_status "Testing honeypot port connectivity from external network..."
    
    # Test SSH honeypot
    if timeout 10 bash -c "echo 'test' | nc -w 5 ${DECOY_PUBLIC_IP} 2222" 2>/dev/null; then
        print_status "SSH Honeypot (port 2222): ACCESSIBLE from external"
    else
        print_warning "SSH Honeypot (port 2222): NOT ACCESSIBLE from external - check security groups"
    fi
    
    # Test Telnet honeypot
    if timeout 10 bash -c "echo 'test' | nc -w 5 ${DECOY_PUBLIC_IP} 2223" 2>/dev/null; then
        print_status "Telnet Honeypot (port 2223): ACCESSIBLE from external"
    else
        print_warning "Telnet Honeypot (port 2223): NOT ACCESSIBLE from external - check security groups"
    fi
    
    # Test HTTP honeypot
    if timeout 10 curl -s --connect-timeout 5 "http://${DECOY_PUBLIC_IP}" >/dev/null 2>&1; then
        print_status "HTTP Honeypot (port 80): ACCESSIBLE from external"
    else
        print_warning "HTTP Honeypot (port 80): NOT ACCESSIBLE from external - check security groups"
    fi
    
    # Test HTTPS if available
    if timeout 10 curl -s --connect-timeout 5 -k "https://${DECOY_PUBLIC_IP}" >/dev/null 2>&1; then
        print_status "HTTPS Honeypot (port 443): ACCESSIBLE from external"
    else
        print_warning "HTTPS Honeypot (port 443): NOT ACCESSIBLE from external"
    fi
}

# Generate deployment report
generate_report() {
    print_status "Generating deployment report..."
    
    REPORT_FILE="logs/deployment_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$REPORT_FILE" << EOF
CTI Honeypot Deployment Report
==============================
Deployment Date: $(date)
Target Machine: ${DECOY_PRIVATE_IP} (${DECOY_PUBLIC_IP})
Deployed By: $(whoami)
Deployment Host: $(hostname)

Honeypots Deployed:
- SSH Honeypot: Port 2222
- Telnet Honeypot: Port 2223
- HTTP Honeypot: Port 80
- HTTPS Honeypot: Port 443 (if configured)

External Access URLs:
- SSH: ssh -p 2222 test@${DECOY_PUBLIC_IP}
- Telnet: telnet ${DECOY_PUBLIC_IP} 2223
- HTTP: http://${DECOY_PUBLIC_IP}
- HTTPS: https://${DECOY_PUBLIC_IP}

Management Commands:
- Collect logs: ./scripts/collect_logs.sh
- Monitor live: ./scripts/monitor_honeypots.sh
- Restart services: ansible honeypots -i ansible/inventory/hosts.ini -m shell -a "cd /opt/honeypot/config && docker compose -f ssh-telnet-compose.yml restart && docker compose -f http-compose.yml restart" --become-user=ubuntu

Container Status:
EOF

    # Append container status to report
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /opt/honeypot/config && echo '=== SSH/Telnet Containers ===' && docker compose -f ssh-telnet-compose.yml ps && echo '=== HTTP Containers ===' && docker compose -f http-compose.yml ps" \
        --become-user=ubuntu >> "$REPORT_FILE" 2>&1 || echo "Could not fetch container status" >> "$REPORT_FILE"
    
    print_status "Deployment report saved to: $REPORT_FILE"
}

# Cleanup function for failed deployments
cleanup_failed_deployment() {
    if [ "$?" -ne 0 ]; then
        print_error "Deployment failed. Running cleanup..."
        ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
            -a "cd /opt/honeypot/config && docker compose -f ssh-telnet-compose.yml down --remove-orphans && docker compose -f http-compose.yml down --remove-orphans" \
            --become-user=ubuntu || true
    fi
}

# Set trap for cleanup on failure
trap cleanup_failed_deployment ERR

# Main execution function
main() {
    print_status "Starting CTI honeypot deployment process..."
    
    validate_requirements
    test_connectivity
    pre_deployment_checks
    deploy_honeypots
    verify_deployment
    test_honeypot_ports
    generate_report
    
    echo -e "${GREEN}=== Multi-Protocol Honeypot Deployment Complete ===${NC}"
    echo -e "${BLUE}Deployment Summary:${NC}"
    echo "  • Target Machine: ${DECOY_PRIVATE_IP} (internal) / ${DECOY_PUBLIC_IP} (external)"
    echo "  • SSH Honeypot: Port 2222"
    echo "  • Telnet Honeypot: Port 2223" 
    echo "  • HTTP Honeypot: Port 80"
    echo "  • HTTPS Honeypot: Port 443"
    echo ""
    echo -e "${BLUE}Testing Commands (External Access):${NC}"
    echo "  ssh -p 2222 test@${DECOY_PUBLIC_IP}"
    echo "  telnet ${DECOY_PUBLIC_IP} 2223"
    echo "  curl http://${DECOY_PUBLIC_IP}"
    echo "  curl -k https://${DECOY_PUBLIC_IP}"
    echo ""
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  ./scripts/collect_logs.sh    # Collect all honeypot logs"
    echo "  ./scripts/monitor_honeypots.sh # Monitor live activity"
    echo ""
    echo -e "${GREEN}Deployment report saved in logs/ directory${NC}"
}

# Run main function with all arguments
main "$@"
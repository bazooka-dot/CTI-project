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

echo -e "${BLUE}=== CTI Multi-Protocol Honeypot Management ===${NC}"
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
    
    # Install required collections
    if ! ansible-galaxy collection list 2>/dev/null | grep -q community.docker; then
        print_status "Installing community.docker collection..."
        ansible-galaxy collection install community.docker --force
    fi
    
    print_status "Requirements validated successfully"
}

# Test connectivity
test_connectivity() {
    print_status "Testing connectivity to target hosts..."
    if ansible all -i "ansible/inventory/hosts.ini" -m ping --timeout=30; then
        print_status "Connectivity test passed"
    else
        print_error "Connectivity test failed - check SSH keys and network connectivity"
        exit 1
    fi
}

# Check existing honeypots on decoy machine
check_existing_honeypots() {
    print_status "Checking existing honeypots on decoy machine..."
    
    # Check if honeypots exist
    if ansible honeypots -i "ansible/inventory/hosts.ini" -m stat \
        -a "path=/home/ubuntu/honeypot/cowrie/docker-compose.yml" \
        --become-user=ubuntu 2>/dev/null | grep -q "exists.*true"; then
        print_status "Cowrie honeypot found at /home/ubuntu/honeypot/cowrie/"
    else
        print_error "Cowrie honeypot not found on decoy machine"
        exit 1
    fi
    
    if ansible honeypots -i "ansible/inventory/hosts.ini" -m stat \
        -a "path=/home/ubuntu/honeypot/http/docker-compose.yml" \
        --become-user=ubuntu 2>/dev/null | grep -q "exists.*true"; then
        print_status "HTTP honeypot found at /home/ubuntu/honeypot/http/"
    else
        print_error "HTTP honeypot not found on decoy machine"
        exit 1
    fi
    
    # Show current status
    print_status "Current honeypot directory structure:"
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "ls -la /home/ubuntu/honeypot/" --become-user=ubuntu
}

# Pre-deployment checks
pre_deployment_checks() {
    print_status "Running pre-deployment checks..."
    
    # Check target system
    ansible honeypots -i "ansible/inventory/hosts.ini" -m setup \
        -a "filter=ansible_distribution*,ansible_memtotal_mb" --become || exit 1
    
    # Check Docker
    ansible honeypots -i "ansible/inventory/hosts.ini" -m systemd \
        -a "name=docker" --become || exit 1
    
    print_status "Pre-deployment checks completed successfully"
}

# Deploy/restart honeypots
deploy_honeypots() {
    print_status "Managing existing honeypots on decoy machine..."
    
    mkdir -p logs
    
    if ansible-playbook -i "ansible/inventory/hosts.ini" "ansible/playbooks/deploy_ssh_honeypot.yml" -v; then
        print_status "Honeypot management completed successfully"
    else
        print_error "Honeypot management failed"
        exit 1
    fi
}

# Verify deployment
verify_deployment() {
    print_status "Verifying honeypot status..."
    
    sleep 10
    
    # Show all running containers with simple docker ps
    print_status "Current container status:"
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "docker ps" \
        --become-user=ubuntu
    
    # Check specific honeypot logs
    print_status "Recent honeypot logs:"
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /home/ubuntu/honeypot/cowrie && echo '=== COWRIE ===' && (docker compose logs --tail=3 2>/dev/null || docker-compose logs --tail=3)" \
        --become-user=ubuntu || true
    
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "cd /home/ubuntu/honeypot/http && echo '=== HTTP ===' && (docker compose logs --tail=3 2>/dev/null || docker-compose logs --tail=3)" \
        --become-user=ubuntu || true
    
    print_status "Verification completed"
}

# Test external connectivity
test_honeypot_ports() {
    print_status "Testing external connectivity..."
    
    # Test ports
    for port in 2222 2223 80; do
        if timeout 10 nc -z ${DECOY_PUBLIC_IP} ${port} 2>/dev/null; then
            print_status "Port ${port}: ACCESSIBLE"
        else
            print_warning "Port ${port}: NOT ACCESSIBLE - check security groups"
        fi
    done
}

# Generate simple report
generate_report() {
    print_status "Generating status report..."
    
    REPORT_FILE="logs/honeypot_status_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "CTI Honeypot Status Report" > "$REPORT_FILE"
    echo "=========================" >> "$REPORT_FILE"
    echo "Date: $(date)" >> "$REPORT_FILE"
    echo "Target: ${DECOY_PRIVATE_IP} (${DECOY_PUBLIC_IP})" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    ansible honeypots -i "ansible/inventory/hosts.ini" -m shell \
        -a "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'" \
        --become-user=ubuntu >> "$REPORT_FILE" 2>&1 || echo "Could not fetch status" >> "$REPORT_FILE"
    
    print_status "Report saved to: $REPORT_FILE"
}

# Main execution
main() {
    print_status "Starting honeypot management process..."
    
    validate_requirements
    test_connectivity
    check_existing_honeypots
    pre_deployment_checks
    deploy_honeypots
    verify_deployment
    test_honeypot_ports
    generate_report
    
    echo -e "${GREEN}=== Honeypot Management Complete ===${NC}"
    echo -e "${BLUE}Access Points:${NC}"
    echo "SSH: ssh -p 2222 test@${DECOY_PUBLIC_IP}"
    echo "Telnet: telnet ${DECOY_PUBLIC_IP} 2223"
    echo "HTTP: curl http://${DECOY_PUBLIC_IP}"
    echo ""
    echo -e "${YELLOW}Note: Managing existing honeypots on decoy machine${NC}"
}

main "$@"v
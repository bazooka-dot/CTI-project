#!/bin/bash

###############################################################################
# CTI Lab - SSH Connectivity Diagnostic Tool
# Purpose: Verify SSH access from orchestrator to all lab VMs
# Usage: ./ssh_connectivity_test.sh [target_host]
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default targets
TARGETS=("cti-decoy-01:10.0.2.48" "cti-core-01:10.0.1.81")
SSH_USER="ubuntu"

echo "=============================================="
echo "  CTI Lab - SSH Connectivity Diagnostic"
echo "=============================================="
echo ""
echo "Current host: $(hostname)"
echo "Current user: $(whoami)"
echo "Current IP: $(hostname -I | awk '{print $1}')"
echo ""

# If specific target provided as argument
if [ -n "$1" ]; then
    TARGETS=("$1")
fi

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

# Function to test single target
test_target() {
    local target_name=$1
    local target_ip=$2
    
    echo ""
    echo "================================================"
    echo "Testing: $target_name ($target_ip)"
    echo "================================================"
    
    # 1. Network connectivity
    echo ""
    echo "1. Network Connectivity Test"
    echo "   Pinging $target_ip..."
    if ping -c 2 -W 3 $target_ip >/dev/null 2>&1; then
        print_status 0 "Ping successful"
    else
        print_status 1 "Ping failed (ICMP may be blocked - not critical)"
    fi
    
    # 2. SSH Port check
    echo ""
    echo "2. SSH Port (22) Test"
    echo "   Checking if port 22 is open..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$target_ip/22" 2>/dev/null; then
        print_status 0 "Port 22 is open"
    else
        print_status 1 "Port 22 is closed or filtered"
        echo -e "   ${YELLOW}Action Required:${NC} Check Security List in Oracle Cloud Console"
        echo "   Add ingress rule: Source CIDR 10.0.1.0/24, Protocol TCP, Port 22"
        return 1
    fi
    
    # 3. SSH Keys check
    echo ""
    echo "3. SSH Keys Check"
    if [ -f ~/.ssh/id_rsa ]; then
        print_status 0 "Found SSH key: ~/.ssh/id_rsa"
        SSH_KEY="~/.ssh/id_rsa"
    elif [ -f ~/.ssh/id_ed25519 ]; then
        print_status 0 "Found SSH key: ~/.ssh/id_ed25519"
        SSH_KEY="~/.ssh/id_ed25519"
    else
        print_status 1 "No SSH private key found"
        echo "   Available files in ~/.ssh/:"
        ls -la ~/.ssh/ 2>/dev/null || echo "   ~/.ssh/ directory not found"
        echo -e "   ${YELLOW}Action Required:${NC} Generate SSH key with:"
        echo "   ssh-keygen -t ed25519 -C 'cti-orchestrator' -f ~/.ssh/id_ed25519 -N ''"
        return 1
    fi
    
    # 4. SSH Connection test
    echo ""
    echo "4. SSH Connection Test"
    echo "   Connecting as $SSH_USER@$target_ip..."
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes $SSH_USER@$target_ip "hostname && whoami" >/dev/null 2>&1; then
        print_status 0 "SSH connection successful"
        REMOTE_HOSTNAME=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes $SSH_USER@$target_ip "hostname" 2>/dev/null)
        echo "   Remote hostname: $REMOTE_HOSTNAME"
    else
        print_status 1 "SSH connection failed"
        echo -e "   ${YELLOW}Troubleshooting:${NC}"
        echo "   1. Verify SSH key is in target's ~/.ssh/authorized_keys"
        echo "   2. Run: ssh-copy-id -i $SSH_KEY $SSH_USER@$target_ip"
        echo "   3. Or manually add public key via Oracle Cloud Console"
        return 1
    fi
    
    # 5. Sudo access test
    echo ""
    echo "5. Passwordless Sudo Test"
    echo "   Testing sudo access..."
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes $SSH_USER@$target_ip "sudo -n whoami" >/dev/null 2>&1; then
        print_status 0 "Passwordless sudo works"
    else
        print_status 1 "Sudo requires password"
        echo -e "   ${YELLOW}Action Required:${NC} Configure passwordless sudo on $target_name:"
        echo "   sudo visudo"
        echo "   Add line: $SSH_USER ALL=(ALL) NOPASSWD:ALL"
    fi
    
    # 6. System info
    echo ""
    echo "6. System Information"
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no $SSH_USER@$target_ip "uname -a" 2>/dev/null; then
        print_status 0 "Command execution successful"
    else
        print_status 1 "Command execution failed"
    fi
    
    # 7. Ansible test
    echo ""
    echo "7. Ansible Connectivity Test"
    if command -v ansible >/dev/null 2>&1; then
        if ansible all -i "$target_ip," -u $SSH_USER -m ping >/dev/null 2>&1; then
            print_status 0 "Ansible can connect"
        else
            print_status 1 "Ansible connection failed"
        fi
    else
        echo -e "   ${YELLOW}⚠${NC} Ansible not installed - skipping test"
    fi
    
    echo ""
    echo "================================================"
    echo "Result for $target_name: COMPLETE"
    echo "================================================"
}

# Main execution
echo "Testing SSH connectivity to CTI Lab VMs..."
echo ""

for target in "${TARGETS[@]}"; do
    IFS=':' read -r name ip <<< "$target"
    test_target "$name" "$ip"
done

echo ""
echo "=============================================="
echo "  Diagnostic Complete"
echo "=============================================="
echo ""
echo "Summary:"
echo "  - If all tests passed: You're ready for Ansible!"
echo "  - If tests failed: Follow the action items above"
echo ""
echo "Next steps:"
echo "  1. Fix any failed tests"
echo "  2. Run: cd /opt/cti-project/ansible"
echo "  3. Test: ansible -i inventory/hosts.ini all -m ping"
echo ""

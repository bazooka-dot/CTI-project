#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd "$(dirname "$0")/.."

echo -e "${BLUE}=== Multi-Protocol Honeypot Log Collection ===${NC}"

# Create timestamped log directory
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOG_DIR="logs/collected_$TIMESTAMP"
mkdir -p "$LOG_DIR"

echo -e "${GREEN}[INFO]${NC} Collecting logs to: $LOG_DIR"

# Collect honeypot application logs
echo "Fetching honeypot application logs..."
ansible honeypots -i ansible/inventory/hosts.ini -m fetch \
    -a "src=/opt/honeypot/logs/ dest=$LOG_DIR/ flat=no" \
    --become || true

# Collect SSH/Telnet container logs
echo "Collecting SSH/Telnet container logs..."
ansible honeypots -i ansible/inventory/hosts.ini -m shell \
    -a "cd /opt/honeypot/config && docker compose -f ssh-telnet-compose.yml logs --no-color --timestamps" \
    --become-user=ubuntu > "$LOG_DIR/ssh-telnet-containers.log" 2>&1 || true

# Collect HTTP container logs  
echo "Collecting HTTP container logs..."
ansible honeypots -i ansible/inventory/hosts.ini -m shell \
    -a "cd /opt/honeypot/config && docker compose -f http-compose.yml logs --no-color --timestamps" \
    --become-user=ubuntu > "$LOG_DIR/http-containers.log" 2>&1 || true

# Collect container status
echo "Collecting container status..."
ansible honeypots -i ansible/inventory/hosts.ini -m shell \
    -a "cd /opt/honeypot/config && echo '=== SSH/Telnet Containers ===' && docker compose -f ssh-telnet-compose.yml ps && echo '=== HTTP Containers ===' && docker compose -f http-compose.yml ps" \
    --become-user=ubuntu > "$LOG_DIR/container-status.log" 2>&1 || true

# Collect system information
echo "Collecting system information..."
ansible honeypots -i ansible/inventory/hosts.ini -m shell \
    -a "echo '=== System Info ===' && uname -a && echo '=== Disk Usage ===' && df -h && echo '=== Memory Usage ===' && free -m && echo '=== Docker Info ===' && docker system df" \
    --become > "$LOG_DIR/system-info.log" 2>&1 || true

# Create comprehensive summary
cat > "$LOG_DIR/collection_summary.txt" << EOF
Multi-Protocol Honeypot Log Collection Summary
==============================================
Collection Time: $(date)
Collection Directory: $LOG_DIR
Target Hosts: $(ansible honeypots -i ansible/inventory/hosts.ini --list-hosts | grep -v 'hosts (' | tr -d ' ')

Honeypot Types:
- SSH Honeypot (Port 2222)
- Telnet Honeypot (Port 2223)  
- HTTP Honeypot (Port 80)

Files Collected:
$(find "$LOG_DIR" -type f -exec basename {} \; | sort)

Total Collection Size: $(du -sh "$LOG_DIR" | cut -f1)

Log Analysis Commands:
- View SSH attempts: grep -r "SSH\|ssh" $LOG_DIR/
- View HTTP requests: grep -r "GET\|POST" $LOG_DIR/
- View failed logins: grep -r "failed\|Failed\|FAIL" $LOG_DIR/
- View attack patterns: grep -r "attack\|exploit\|malware" $LOG_DIR/
EOF

echo -e "${GREEN}=== Log Collection Complete ===${NC}"
echo "Logs saved to: $LOG_DIR"
echo "Summary available in: $LOG_DIR/collection_summary.txt"
echo ""
echo -e "${YELLOW}Quick Analysis Commands:${NC}"
echo "  cat $LOG_DIR/collection_summary.txt"
echo "  grep -r 'failed' $LOG_DIR/"
echo "  tail -f $LOG_DIR/*.log"
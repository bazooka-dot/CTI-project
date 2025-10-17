#!/bin/bash

# Get the machine's IP address automatically
get_machine_ip() {
    # Try to get external IP first
    external_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
    
    if [ -n "$external_ip" ]; then
        echo "$external_ip"
        return
    fi
    
    # Fall back to local network IP
    local_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}')
    
    if [ -n "$local_ip" ]; then
        echo "$local_ip"
        return
    fi
    
    # Final fallback to localhost
    echo "127.0.0.1"
}

MACHINE_IP=$(get_machine_ip)
echo "Detected machine IP: $MACHINE_IP"

# Test the backend API endpoints
echo "Testing backend API endpoints..."

echo "1. Testing /api/auth endpoint:"
curl -X POST http://$MACHINE_IP:4000/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}' \
  --connect-timeout 5

echo -e "\n\n2. Testing /admin endpoint:"
curl -X POST http://$MACHINE_IP:4000/admin \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"toor"}' \
  --connect-timeout 5

echo -e "\n\n3. Testing health endpoint:"
curl -X GET http://$MACHINE_IP:4000/health --connect-timeout 5

echo -e "\n\nDone testing backend endpoints."
#!/bin/sh
set -e

echo "Initializing Cowrie configuration files and directories..."

# Remove any existing directories with these names
if [ -d /config/cowrie.cfg ]; then
    echo "Removing existing cowrie.cfg directory..."
    rm -rf /config/cowrie.cfg
fi

if [ -d /config/userdb.txt ]; then
    echo "Removing existing userdb.txt directory..."
    rm -rf /config/userdb.txt
fi

# Create necessary directories with proper permissions
echo "Creating required directories..."
mkdir -p /logs /downloads /tty /config

# Set permissions for directories (world writable to avoid permission issues)
chmod 777 /logs /downloads /tty /config

echo "Directories created and permissions set"

# Create cowrie.cfg if it doesn't exist
if [ ! -f /config/cowrie.cfg ]; then
    echo "Generating cowrie.cfg..."
    cat > /config/cowrie.cfg << 'EOF'
[honeypot]
hostname = ubuntu-server
backend = shell
auth_class = UserDB
download_path = /cowrie/var/lib/cowrie/downloads
ttylog = true
ttylog_path = /cowrie/var/lib/cowrie/tty

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = /cowrie/var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = /cowrie/var/log/cowrie/cowrie.log

[shell]
userdb_file = etc/userdb.txt

# Disable issue.net banner to avoid file not found errors
[ssh_banner]
enabled = false

[telnet_banner]
enabled = false
EOF
    echo "cowrie.cfg generated successfully"
else
    echo "cowrie.cfg already exists, skipping..."
fi

# Create userdb.txt if it doesn't exist
if [ ! -f /config/userdb.txt ]; then
    echo "Generating userdb.txt..."
    cat > /config/userdb.txt << 'EOF'
root:0:123456
admin:1000:admin
user:1001:password
guest:1002:guest
pi:1003:raspberry
ubuntu:1004:ubuntu
test:1005:test
EOF
    echo "userdb.txt generated successfully"
else
    echo "userdb.txt already exists, skipping..."
fi

echo "Configuration initialization complete!"

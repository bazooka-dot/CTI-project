#!/bin/bash

# HTTP/HTTPS Honeypot Entrypoint Script

echo "Starting HTTP/HTTPS Honeypot..."
echo "Hostname: $(hostname)"
echo "Date: $(date)"

# Generate SSL certificates if they don't exist
SSL_DIR="/tmp/ssl"
mkdir -p $SSL_DIR

if [ ! -f $SSL_DIR/server.crt ] || [ ! -f $SSL_DIR/server.key ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SSL_DIR/server.key \
        -out $SSL_DIR/server.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=api-server-prod-01"
    
    chmod 600 $SSL_DIR/server.key
    chmod 644 $SSL_DIR/server.crt
    echo "SSL certificates generated successfully."
fi

# Create web root if it doesn't exist
mkdir -p /var/www/html

# Create a simple index page
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>API Server - Production</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .status { background-color: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .endpoints { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .endpoint { margin: 10px 0; font-family: monospace; background: #e9ecef; padding: 5px 10px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Server - Production Environment</h1>
        
        <div class="status">
            <strong>Status:</strong> Online and operational
        </div>
        
        <h2>Available Endpoints</h2>
        <div class="endpoints">
            <div class="endpoint">GET /api/status - System status</div>
            <div class="endpoint">GET /api/health - Health check</div>
            <div class="endpoint">GET /api/version - API version</div>
        </div>
        
        <p><strong>Server:</strong> api-server-prod-01</p>
        <p><strong>Environment:</strong> Production</p>
        <p><strong>Last Updated:</strong> $(date)</p>
    </div>
</body>
</html>
EOF

# Create honeypot log files (after volume mount)
echo "Creating honeypot log files..."
mkdir -p /var/log/honeypot
touch /var/log/honeypot/access.log
touch /var/log/honeypot/error.log
touch /var/log/honeypot/attacks.log

# Ensure proper permissions
chown -R nginx:nginx /var/www/html
chown -R nginx:nginx /var/log/honeypot
chmod -R 755 /var/www/html
chmod -R 755 /var/log/honeypot

# Test nginx configuration
echo "Testing nginx configuration..."
nginx -t

if [ $? -ne 0 ]; then
    echo "ERROR: nginx configuration test failed!"
    exit 1
fi

echo "Configuration test passed."
echo "Starting nginx..."

# Execute the main command
exec "$@"
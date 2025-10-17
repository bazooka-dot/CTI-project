#!/bin/sh

echo "Starting CTI Cloud Frontend..."

# Generate SSL certificates
mkdir -p /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/server.crt ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/C=US/ST=State/L=City/O=CTI-Cloud/CN=localhost"
    chmod 600 /etc/nginx/ssl/server.key
    chmod 644 /etc/nginx/ssl/server.crt
    echo "SSL certificates generated."
fi

# Create log files (needed for volume mounts)
echo "Creating log files..."
mkdir -p /var/log/nginx
touch /var/log/nginx/access.log
touch /var/log/nginx/access.json
touch /var/log/nginx/error.log  
touch /var/log/nginx/attacks.log
echo "Log files created."

# Start Next.js app in background
echo "Starting Next.js application..."
cd /
HOSTNAME=0.0.0.0 PORT=3000 node server.js &

# Wait a moment for Next.js to start
sleep 3

# Start nginx
echo "Starting nginx..."
nginx -g "daemon off;"
# HTTP/HTTPS Honeypot Dockerfile
FROM nginx:alpine

# Install additional tools for logging and monitoring
RUN apk add --no-cache \
    curl \
    wget \
    net-tools \
    bash \
    openssl

# Create honeypot directories
RUN mkdir -p /var/log/honeypot /etc/nginx/ssl

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Set proper permissions for SSL directory
RUN chmod 755 /etc/nginx/ssl

# Create honeypot log files
RUN touch /var/log/honeypot/access.log \
          /var/log/honeypot/error.log \
          /var/log/honeypot/attacks.log

# Copy custom entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 80 443 8080 8443

# Start nginx
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
# CTI Cloud Frontend - Next.js with Nginx
FROM node:18-alpine as builder

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
COPY pnpm-lock.yaml ./

# Install pnpm and dependencies
RUN npm install -g pnpm
RUN pnpm install

# Copy source code
COPY . .

# Build the application
RUN pnpm build

# Production stage with nginx
FROM nginx:alpine

# Install openssl and nodejs for SSL certificates and running the app
RUN apk add --no-cache openssl nodejs npm

# Copy built app
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Create nginx configuration
RUN mkdir -p /etc/nginx/conf.d /etc/nginx/ssl

# Copy nginx config
COPY nginx-frontend.conf /etc/nginx/nginx.conf
COPY frontend-sites.conf /etc/nginx/conf.d/default.conf

# Create entrypoint script
COPY entrypoint-frontend.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 80 443 8080

# Start services
CMD ["/entrypoint.sh"]
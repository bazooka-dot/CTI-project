FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Create log directory
RUN mkdir -p /var/log/backend

# Expose port
EXPOSE 4000

# Start the application
CMD ["npm", "start"]
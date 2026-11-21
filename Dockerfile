# =============================================================================
# KASED KARIM LUXURY LIGHTING - PRODUCTION CONTAINER IMAGE
# Compatible with: Docker & Podman
# Security Standard: OWASP Docker Top 10, Non-Root User Execution
# =============================================================================

FROM node:22-alpine AS base

# Install necessary runtime libraries
RUN apk add --no-cache curl postgresql-client tzdata \
    && cp /usr/share/zoneinfo/Africa/Cairo /etc/localtime \
    && echo "Africa/Cairo" > /etc/timezone

WORKDIR /app

# Copy package descriptors
COPY package*.json ./

# Install production dependencies
RUN npm install --omit=dev --legacy-peer-deps || npm install --omit=dev

# Copy application source code
COPY . .

# Set secure file permissions and non-root execution
RUN chown -R node:node /app

USER node

# Default Environment Variables
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0

EXPOSE 3000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/db-health || exit 1

# Start the unified portable server
CMD ["node", "server.js"]

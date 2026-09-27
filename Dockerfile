# ==============================================================================
# CyberWorld Frontend — Production Multi-Stage Dockerfile
# Stage 1: Build React 19 + Vite + TypeScript application
# Stage 2: Serve optimized bundle via Alpine Nginx
# ==============================================================================

# --- Stage 1: Build ---
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies deterministically
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code and build production assets
COPY . .
RUN npm run build

# --- Stage 2: Runtime Web Server ---
FROM nginx:alpine

# Remove default nginx configurations and static templates
RUN rm -rf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/*

# Copy custom reverse-proxy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled SPA bundle from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

# Health check ensuring Nginx is serving the frontend index
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

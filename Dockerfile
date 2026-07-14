# --- STAGE 1: Build the React Client SPA ---
FROM node:20-alpine AS client-builder
WORKDIR /app/client

# Copy client configs
COPY client/package*.json ./
RUN npm ci

# Copy client source code
COPY client/ ./
# Build production bundle (produces /app/client/dist)
RUN npm run build

# --- STAGE 2: Build the Production Express Backend Runner ---
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Copy backend configs and install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy backend source code
COPY server.js ./
COPY data/ ./data/
COPY public/ ./public/
COPY scripts/ ./scripts/
COPY index.html ./
COPY verify.html ./

# Copy compiled frontend assets from Builder Stage
COPY --from=client-builder /app/client/dist ./client/dist

# Expose port and run server
EXPOSE 3000
CMD ["node", "server.js"]

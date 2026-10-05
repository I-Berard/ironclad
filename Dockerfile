# Stage 1: Build the Vite frontend
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend

# Copy frontend package files and install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy the rest of the frontend source and build
COPY frontend/ ./
RUN npm run build

# Stage 2: Setup the backend and final image
FROM node:18-alpine
WORKDIR /app

# Copy the SQLite schema required by the backend
COPY schema.sql ./

# Setup backend directory
WORKDIR /app/backend

# Copy backend package files and install dependencies
COPY backend/package*.json ./
RUN npm install

# Copy the rest of the backend source
COPY backend/ ./

# Copy the built frontend static files from Stage 1 into the backend's public directory
COPY --from=frontend-builder /app/frontend/dist ./public

# Expose the backend port
EXPOSE 5000

# Start the Node.js backend server
CMD ["node", "server.js"]

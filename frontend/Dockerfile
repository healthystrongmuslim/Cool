# Stage 1: Build the frontend using Node.js
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy the rest of the frontend code
COPY frontend/ .

# Build the Vite project
RUN npm run build

# Stage 2: Serve the frontend using Nginx
FROM nginx:alpine

# Copy built files to Nginx's public directory
COPY --from=builder /app/dist /usr/share/nginx/html

# Replace the default Nginx config with a custom one
RUN rm /etc/nginx/conf.d/default.conf
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
# SmartFuzz frontend — multi-stage Vite build, served by nginx.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app

# Install deps with a clean, reproducible lockfile install.
COPY package.json package-lock.json* ./
RUN npm ci

# Source + build.
COPY . .
RUN npm run build

# ── Stage 2: serve ────────────────────────────────────────────────────────────
FROM nginx:alpine

# SPA-friendly nginx config — fallback to index.html + /api proxy + /socket.io.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Built static assets.
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

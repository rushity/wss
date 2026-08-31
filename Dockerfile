# ============================================================================
# SentinelScan — Single-container build for Hugging Face Spaces
# Multi-stage: builds React frontend, then bundles with Flask backend
# ============================================================================

# --- Stage 1: Build React frontend ---
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# --- Stage 2: Python backend + built frontend ---
FROM python:3.11-slim

WORKDIR /app

# Install system deps: gcc (C extensions), nmap (Nmap scanner), libpq (psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ backend/
COPY app.py .
COPY .env.example .

# Copy built React frontend from Stage 1
COPY --from=frontend-build /app/frontend/dist/ frontend/dist/

# Production env defaults (HF Secrets override these at runtime)
ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

EXPOSE 7860

COPY start.sh .
RUN chmod +x start.sh
CMD ["./start.sh"]

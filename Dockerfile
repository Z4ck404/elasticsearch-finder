# Elasticsearch Finder - Docker Image
# Multi-stage build for smaller final image
# Uses uv for fast dependency management

# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set uv environment variables
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=never
ENV UV_PYTHON=python3.11

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install dependencies using uv
RUN uv pip install --system --no-cache .

# Final stage
FROM python:3.11-slim

LABEL maintainer="Z4ck404"
LABEL description="Elasticsearch Finder - Find and analyze open Elasticsearch instances"
LABEL version="2.0.0"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/esf /usr/local/bin/esf

# Copy application code
COPY src/ ./src/
COPY esf.py ./
COPY README.md LICENSE ./

# Create output directory
RUN mkdir -p /app/output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default output directory
WORKDIR /app/output

# Entry point
ENTRYPOINT ["esf"]

# Default command (show help)
CMD ["--help"]

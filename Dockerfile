# Multi-stage Dockerfile for ViolentUTF API

# Build stage - uses full image with gcc pre-installed

FROM python:3.13 as builder

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies (using pre-installed gcc)
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r requirements.txt

# Runtime base stage - uses slim image for security

FROM python:3.13-slim as base

WORKDIR /app

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy wheels from builder
COPY --from=builder /app/wheels /wheels

# Install dependencies from pre-built wheels (no gcc needed)
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* \
    && rm -rf /wheels

# Copy application code
COPY --chown=appuser:appuser violentutf_api/ ./violentutf_api/
COPY --chown=appuser:appuser tests/ ./tests/
COPY --chown=appuser:appuser pytest.ini .

# Switch to non-root user
USER appuser

# Development stage
FROM base as development
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
USER root
RUN pip install --no-cache-dir "uvicorn[standard]>=0.27.0,<0.31.0"
USER appuser
CMD ["uvicorn", "violentutf_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Test stage
FROM base as test
USER root
RUN pip install --no-cache-dir pytest==8.3.5 pytest-cov==6.2.1
USER appuser
CMD ["pytest", "-v"]

# Production stage
FROM base as production
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "violentutf_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

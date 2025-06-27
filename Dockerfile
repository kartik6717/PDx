# Multi-stage Dockerfile for PDF Scrubber
# Optimized for production deployment

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN chmod +x build.sh && \
    ./build.sh build && \
    strip build/bin/* && \
    mkdir -p /app/dist && \
    cp build/bin/* /app/dist/ && \
    cp *.md /app/dist/

# Production stage
FROM ubuntu:22.04 AS production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r pdfscrubber && useradd -r -g pdfscrubber pdfscrubber

# Create directories
RUN mkdir -p /app/bin /app/docs /app/config /app/data

# Copy binaries and documentation from builder
COPY --from=builder /app/dist/pdfscrubber /app/bin/
COPY --from=builder /app/dist/pdfforensic /app/bin/
COPY --from=builder /app/dist/*.md /app/docs/

# Set permissions
RUN chown -R pdfscrubber:pdfscrubber /app && \
    chmod +x /app/bin/*

# Create volumes for data
VOLUME ["/app/data", "/app/config"]

# Switch to non-root user
USER pdfscrubber

# Set working directory
WORKDIR /app

# Add binaries to PATH
ENV PATH="/app/bin:${PATH}"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pdfscrubber --version || exit 1

# Default command
CMD ["pdfscrubber", "--help"]

# Metadata
LABEL org.opencontainers.image.title="PDF Scrubber"
LABEL org.opencontainers.image.description="Advanced PDF scrubbing and forensic analysis tool"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="PDF Security Tools"
LABEL org.opencontainers.image.source="https://github.com/pdfscrubber/pdfscrubber"
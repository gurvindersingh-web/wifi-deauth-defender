# =============================================================================
# WiFi Deauth Defender — Dockerfile
# =============================================================================
# Multi-stage build for a minimal production image with packet capture
# capabilities.
#
# Build:
#   docker build -t deauth-defender .
#
# Run (requires network capabilities):
#   docker run --rm -it \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     --network=host \
#     -v /path/to/config.yaml:/app/config.yaml:ro \
#     deauth-defender
# =============================================================================

FROM python:3.11-slim AS base

# --- System dependencies for Scapy / wireless tools -------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        iw \
        wireless-tools \
        iproute2 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

# --- Application directory ---------------------------------------------------
WORKDIR /app

# --- Install Python dependencies (cached layer) -----------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy application code ---------------------------------------------------
COPY models.py capture.py detector.py alerter.py main.py ./
COPY config.yaml ./
COPY start.sh ./
RUN chmod +x start.sh

# --- Create non-root user with required capabilities -----------------------
# Note: actual NET_RAW/NET_ADMIN capabilities are granted at container runtime
# via --cap-add flags.  The app user owns the working directory.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

# We do NOT switch to appuser here because raw capture typically requires
# root inside the container.  The --cap-add flags at runtime limit scope.

# --- Health check ------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.close()" || exit 1

# --- Metadata ----------------------------------------------------------------
LABEL maintainer="WiFi Deauth Defender" \
      version="1.0.0" \
      description="Real-time WiFi deauthentication attack detection and alerting"

# --- Entrypoint ---------------------------------------------------------------
ENTRYPOINT ["./start.sh"]
CMD ["-c", "config.yaml"]

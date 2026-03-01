"""
WiFi Deauth Defender Configuration Module
Centralized configuration for detector and alerter components
"""

import os
from pathlib import Path

# ========================================
# DETECTOR CONFIGURATION
# ========================================

# Network interface for packet sniffing
NETWORK_INTERFACE = os.getenv("WIFI_INTERFACE", None)

# Packet capture filter (BPF syntax)
CAPTURE_FILTER = os.getenv("CAPTURE_FILTER", "ip")

# Aggregation window (seconds)
AGGREGATION_WINDOW = int(os.getenv("AGGREGATION_WINDOW", "10"))

# ========================================
# DETECTION THRESHOLDS
# ========================================

# Packets per second threshold for flood detection
FLOOD_THRESHOLD = int(os.getenv("FLOOD_THRESHOLD", "100"))

# Number of unique ports for port scan detection
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))

# UDP traffic ratio threshold
UDP_RATIO_THRESHOLD = float(os.getenv("UDP_RATIO_THRESHOLD", "0.85"))

# Packets per second anomaly threshold
ANOMALY_PPS_THRESHOLD = int(os.getenv("ANOMALY_PPS_THRESHOLD", "500"))

# ========================================
# WEBHOOK ALERTER CONFIGURATION
# ========================================

# n8n webhook endpoint
N8N_WEBHOOK_URL = os.getenv(
    "N8N_WEBHOOK_URL",
    "http://localhost:5678/webhook-test/8a37cb06-dc42-46e7-946a-0521f48f7ca8"
)

# n8n webhook secret (for x-auth-key header)
N8N_WEBHOOK_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "wifi-defender-secret")

# Secure Authentication Token
AUTH_TOKEN = os.getenv("AUTH_TOKEN", N8N_WEBHOOK_SECRET)


# Webhook timeout (seconds)
WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", "5"))

# Maximum retries for failed webhooks
WEBHOOK_MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))

# Delay between webhook retries (seconds)
WEBHOOK_RETRY_DELAY = float(os.getenv("WEBHOOK_RETRY_DELAY", "1.0"))

# Enable/disable webhook alerting
WEBHOOK_ENABLED = os.getenv("WEBHOOK_ENABLED", "true").lower() == "true"

# ========================================
# LOGGING CONFIGURATION
# ========================================

# Alert log directory
LOG_DIR = Path(os.getenv(
    "ALERT_LOG_DIR",
    "/home/thunder/.n8n/alerts"
))

# Maximum log file size before rotation (MB)
MAX_LOG_FILE_SIZE_MB = int(os.getenv("MAX_LOG_FILE_SIZE_MB", "10"))

# Enable file logging
FILE_LOGGING_ENABLED = os.getenv("FILE_LOGGING_ENABLED", "true").lower() == "true"

# ========================================
# ALERT DEDUPLICATION
# ========================================

# Alert dedup cache timeout (seconds)
ALERT_DEDUP_TIMEOUT = int(os.getenv("ALERT_DEDUP_TIMEOUT", "10"))

# ========================================
# PERFORMANCE
# ========================================

# Use PCAP backend for better performance
USE_PCAP = os.getenv("USE_PCAP", "true").lower() == "true"

# Number of worker threads
NUM_WORKERS = int(os.getenv("NUM_WORKERS", "1"))

# ========================================
# VALIDATION
# ========================================

def validate_config():
    """Validate configuration values"""
    errors = []
    
    if FLOOD_THRESHOLD <= 0:
        errors.append("FLOOD_THRESHOLD must be positive")
    
    if PORT_SCAN_THRESHOLD <= 0:
        errors.append("PORT_SCAN_THRESHOLD must be positive")
    
    if not (0 < UDP_RATIO_THRESHOLD <= 1):
        errors.append("UDP_RATIO_THRESHOLD must be between 0 and 1")
    
    if WEBHOOK_MAX_RETRIES < 1:
        errors.append("WEBHOOK_MAX_RETRIES must be at least 1")
    
    if AGGREGATION_WINDOW <= 0:
        errors.append("AGGREGATION_WINDOW must be positive")
    
    return errors

def print_config():
    """Print current configuration"""
    print("\n" + "="*60)
    print("WiFi Deauth Defender Configuration")
    print("="*60)
    print(f"Network Interface:        {NETWORK_INTERFACE or 'auto-detect'}")
    print(f"Capture Filter:           {CAPTURE_FILTER}")
    print(f"Aggregation Window:       {AGGREGATION_WINDOW}s")
    print(f"\nDetection Thresholds:")
    print(f"  Flood Threshold:        {FLOOD_THRESHOLD} packets")
    print(f"  Port Scan Threshold:    {PORT_SCAN_THRESHOLD} unique ports")
    print(f"  UDP Ratio Threshold:    {UDP_RATIO_THRESHOLD}")
    print(f"  Anomaly PPS Threshold:  {ANOMALY_PPS_THRESHOLD} pps")
    print(f"\nWebhook Configuration:")
    print(f"  Enabled:                {WEBHOOK_ENABLED}")
    print(f"  URL:                    {N8N_WEBHOOK_URL}")
    print(f"  Timeout:                {WEBHOOK_TIMEOUT}s")
    print(f"  Max Retries:            {WEBHOOK_MAX_RETRIES}")
    print(f"\nLogging:")
    print(f"  Enabled:                {FILE_LOGGING_ENABLED}")
    print(f"  Directory:              {LOG_DIR}")
    print(f"  Max File Size:          {MAX_LOG_FILE_SIZE_MB}MB")
    print(f"\nPerformance:")
    print(f"  Use PCAP:               {USE_PCAP}")
    print(f"  Worker Threads:         {NUM_WORKERS}")
    print("="*60 + "\n")

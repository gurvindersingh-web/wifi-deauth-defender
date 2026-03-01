import requests
import json
import time
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import os
from detector_config import AUTH_TOKEN

class WebhookAlerter:
    """
    Sends alert events to n8n via webhook
    Handles retries, timeouts, and graceful failures
    """
    
    def __init__(
        self,
        webhook_url: str = None,
        timeout: int = 5,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        enabled: bool = True,
        auth_token: str = None
    ):
        """
        Initialize the webhook alerter
        
        Args:
            webhook_url: URL of n8n webhook endpoint
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            enabled: Whether to send webhooks (useful for testing)
            auth_token: Authentication token for X-Auth-Key header
        """
        self.webhook_url = webhook_url or os.getenv(
            "N8N_WEBHOOK_URL",
            "https://thunder-002.app.n8n.cloud/webhook/8a37cb06-dc42-46e7-946a-0521f48f7ca8"
        )
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enabled = enabled
        self.auth_token = auth_token or AUTH_TOKEN
        self.failed_alerts = []
        
    def send_alert(
        self,
        severity: str,
        attack: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
        alert_id: Optional[str] = None
    ) -> bool:
        """
        Send alert to n8n webhook
        
        Args:
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            attack: Type of attack/anomaly detected
            source: Source IP or identifier
            details: Additional alert details
            alert_id: Unique alert identifier
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            return False
            
        # Extract details for flattened payload
        message = details.get("message", "") if details else ""
        packet_rate = details.get("packet_rate", 0) if details else 0
        
        # Fallback to defaults if not provided but keys exist
        if "packet_count" in (details or {}):
            packet_rate = details["packet_count"]
        elif "pps" in (details or {}):
            packet_rate = details["pps"]

        # Auto-generate message if not provided
        if not message:
            message = f"{severity} Alert: {attack} detected from {source} — {packet_rate} packets"
            
        alert_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "severity": severity,
            "attack": attack,
            "source": source,
            "message": message,
            "packet_rate": packet_rate,
            "details": details or {},
            "alert_id": alert_id or self._generate_alert_id(),
            "system": "wifi_deauth_defender"
        }
        
        return self._send_with_retry(alert_payload)
    
    def _send_with_retry(self, payload: Dict[str, Any]) -> bool:
        """
        Send payload with exponential backoff retry logic
        
        Args:
            payload: Alert payload to send
            
        Returns:
            True if successful, False if all retries failed
        """
        for attempt in range(self.max_retries):
            try:
                headers = {
                    "Content-Type": "application/json"
                }
                
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout,
                    headers=headers
                )
                
                if response.status_code in [200, 201, 202]:
                    print(f"✓ Alert sent to n8n: {payload['attack']} from {payload['source']}")
                    return True
                else:
                    print(f"⚠ n8n webhook returned {response.status_code}: {response.text[:100]}")
                    
            except requests.exceptions.Timeout:
                print(f"⏱ Webhook timeout (attempt {attempt+1}/{self.max_retries})")
            except requests.exceptions.ConnectionError:
                print(f"🔗 Connection error to n8n (attempt {attempt+1}/{self.max_retries})")
            except Exception as e:
                print(f"❌ Error sending webhook: {str(e)}")
            
            # Store failed alert
            if attempt == self.max_retries - 1:
                self.failed_alerts.append(payload)
                print(f"❌ Failed to send alert after {self.max_retries} attempts")
                return False
            
            # Exponential backoff
            wait_time = self.retry_delay * (2 ** attempt)
            time.sleep(wait_time)
        
        return False
    
    def get_failed_alerts(self) -> list:
        """Get list of alerts that failed to send"""
        return self.failed_alerts
    
    def clear_failed_alerts(self) -> None:
        """Clear failed alerts list"""
        self.failed_alerts.clear()
    
    def retry_failed_alerts(self) -> int:
        """
        Retry sending all failed alerts
        
        Returns:
            Number of alerts successfully sent
        """
        if not self.failed_alerts:
            return 0
        
        success_count = 0
        remaining_alerts = []
        
        for alert in self.failed_alerts:
            if self._send_with_retry(alert):
                success_count += 1
            else:
                remaining_alerts.append(alert)
        
        self.failed_alerts = remaining_alerts
        return success_count
    
    @staticmethod
    def _generate_alert_id() -> str:
        """Generate unique alert ID"""
        import uuid
        return str(uuid.uuid4())
    
    def is_webhook_reachable(self) -> bool:
        """Test if webhook endpoint is reachable"""
        try:
            response = requests.get(
                self.webhook_url.rsplit('/', 1)[0],  # Base URL
                timeout=2
            )
            return True
        except Exception as e:
            print(f"Webhook unreachable: {str(e)}")
            return False


# Global instance
_alerter_instance: Optional[WebhookAlerter] = None

def get_alerter(webhook_url: str = None) -> WebhookAlerter:
    """Get or create global alerter instance"""
    global _alerter_instance
    if _alerter_instance is None:
        _alerter_instance = WebhookAlerter(webhook_url=webhook_url)
    return _alerter_instance

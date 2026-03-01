import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
import threading
from collections import deque

class AlertLogger:
    """
    Persists alerts to JSON files with automatic rotation
    Supports querying and aggregation
    """
    
    def __init__(self, log_dir: str = None, max_file_size_mb: int = 10):
        """
        Initialize alert logger
        
        Args:
            log_dir: Directory to store alert logs
            max_file_size_mb: Maximum size before rotating log file
        """
        self.log_dir = Path(log_dir or "/home/thunder/.n8n/alerts")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.lock = threading.Lock()
        
        # In-memory buffer for recent alerts
        self.recent_alerts = deque(maxlen=1000)
        
    def log_alert(self, alert: Dict[str, Any]) -> str:
        """
        Log an alert to persistent storage
        
        Args:
            alert: Alert dictionary with severity, attack_type, source, etc.
            
        Returns:
            Path to the log file
        """
        with self.lock:
            # Add logging timestamp if not present
            if "logged_at" not in alert:
                alert["logged_at"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            
            # Store in memory
            self.recent_alerts.append(alert)
            
            # Get today's log file
            today = datetime.utcnow().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"alerts_{today}.jsonl"
            
            # Check if rotation needed
            if log_file.exists() and log_file.stat().st_size > self.max_file_size:
                # Rotate to archive
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                archive_file = self.log_dir / f"alerts_{today}_{timestamp}.jsonl"
                log_file.rename(archive_file)
            
            # Append alert as JSON line
            with open(log_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
            
            return str(log_file)
    
    def get_recent_alerts(self, limit: int = 100, severity: str = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts from memory
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            List of alert dictionaries
        """
        with self.lock:
            alerts = list(self.recent_alerts)
        
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        
        return alerts[-limit:]
    
    def get_alerts_by_source(self, source: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get all alerts from a specific source"""
        with self.lock:
            alerts = [a for a in self.recent_alerts if a.get("source") == source]
        return alerts[-limit:]
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of recent alerts
        
        Returns:
            Summary dict with counts by severity and attack type
        """
        with self.lock:
            alerts = list(self.recent_alerts)
        
        summary = {
            "total_alerts": len(alerts),
            "by_severity": {},
            "by_attack_type": {},
            "unique_sources": set(),
            "latest_alert_time": None
        }
        
        for alert in alerts:
            # Count by severity
            severity = alert.get("severity", "UNKNOWN")
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            
            # Count by attack type
            attack = alert.get("attack_type", "UNKNOWN")
            summary["by_attack_type"][attack] = summary["by_attack_type"].get(attack, 0) + 1
            
            # Track unique sources
            summary["unique_sources"].add(alert.get("source", "UNKNOWN"))
            
            # Track latest alert
            if alert.get("timestamp"):
                summary["latest_alert_time"] = alert.get("timestamp")
        
        summary["unique_sources"] = len(summary["unique_sources"])
        return summary
    
    def export_alerts(self, output_file: str, start_date: str = None, end_date: str = None):
        """
        Export alerts to a file
        
        Args:
            output_file: Path to output file
            start_date: Filter from date (YYYY-MM-DD)
            end_date: Filter to date (YYYY-MM-DD)
        """
        alerts = []
        
        # Read all alert files in range
        for log_file in sorted(self.log_dir.glob("alerts_*.jsonl")):
            # Skip archives (those with timestamp suffix)
            if log_file.name.count('_') > 2:
                continue
            
            try:
                with open(log_file, "r") as f:
                    for line in f:
                        alert = json.loads(line)
                        # Apply date filter if specified
                        if start_date and alert.get("timestamp", "") < start_date:
                            continue
                        if end_date and alert.get("timestamp", "") > end_date:
                            continue
                        alerts.append(alert)
            except json.JSONDecodeError:
                pass
        
        # Write to output
        with open(output_file, "w") as f:
            json.dump(alerts, f, indent=2)
        
        print(f"✓ Exported {len(alerts)} alerts to {output_file}")
    
    def get_log_files(self) -> List[str]:
        """Get list of all alert log files"""
        return sorted([str(f) for f in self.log_dir.glob("alerts_*.jsonl")])


# Global instance
_logger_instance = None

def get_logger(log_dir: str = None) -> AlertLogger:
    """Get or create global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlertLogger(log_dir=log_dir)
    return _logger_instance

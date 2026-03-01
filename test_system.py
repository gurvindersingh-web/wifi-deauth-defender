#!/usr/bin/env python3
"""
WiFi Deauth Defender - System Testing & Diagnostics
Tests all components of the defense system
"""

import sys
import subprocess
import requests
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import time

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class SystemTester:
    def __init__(self):
        self.results = []
        self.n8n_url = "http://localhost:5678"
        self.webhook_url = f"{self.n8n_url}/webhook/wifi-deauth-alerts"
        
    def log(self, status, message, detail=""):
        """Log test result"""
        symbol = f"{GREEN}✓{RESET}" if status == "PASS" else f"{RED}✗{RESET}"
        self.results.append((status, message))
        print(f"{symbol} {message}")
        if detail:
            print(f"  {YELLOW}→{RESET} {detail}")
    
    def test_docker(self):
        """Test Docker installation and daemon"""
        print(f"\n{BLUE}[1] Docker & n8n Container{RESET}")
        
        # Check Docker installed
        try:
            result = subprocess.run(["docker", "--version"], 
                                  capture_output=True, text=True)
            self.log("PASS", "Docker installed", result.stdout.strip())
        except FileNotFoundError:
            self.log("FAIL", "Docker not found", "Install Docker: https://docs.docker.com/get-docker/")
            return False
        
        # Check Docker daemon
        try:
            result = subprocess.run(["docker", "info"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.log("PASS", "Docker daemon is running")
            else:
                self.log("FAIL", "Docker daemon error", "Try: sudo systemctl start docker")
                return False
        except subprocess.TimeoutExpired:
            self.log("FAIL", "Docker daemon timeout", "Docker may not be running")
            return False
        
        # Check n8n container
        try:
            result = subprocess.run(["docker", "ps", "-a"], 
                                  capture_output=True, text=True)
            if "n8n" in result.stdout:
                self.log("PASS", "n8n container exists")
            else:
                self.log("FAIL", "n8n container not found", "Container not yet created")
                return False
        except Exception as e:
            self.log("FAIL", "Container check failed", str(e))
            return False
        
        return True
    
    def test_n8n_health(self):
        """Test n8n service health"""
        print(f"\n{BLUE}[2] n8n Service Health{RESET}")
        
        try:
            response = requests.get(f"{self.n8n_url}/healthz", timeout=5)
            if response.status_code == 200:
                self.log("PASS", "n8n health check passed")
                return True
            else:
                self.log("FAIL", "n8n health check failed", 
                        f"Status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.log("FAIL", "Cannot connect to n8n", 
                    "n8n may not be running or accessible")
            return False
        except requests.exceptions.Timeout:
            self.log("FAIL", "n8n health check timeout", 
                    "n8n is starting or unresponsive")
            return False
        except Exception as e:
            self.log("FAIL", "n8n health check error", str(e))
            return False
    
    def test_webhook_endpoint(self):
        """Test webhook endpoint"""
        print(f"\n{BLUE}[3] Webhook Endpoint{RESET}")
        
        test_alert = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "severity": "LOW",
            "attack_type": "Test Alert",
            "source": "127.0.0.1",
            "details": {"test": True},
            "alert_id": "test-" + str(int(time.time())),
            "system": "wifi_deauth_defender"
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=test_alert,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code in [200, 201, 202]:
                self.log("PASS", "Webhook endpoint responding", 
                        f"Status: {response.status_code}")
                return True
            else:
                self.log("FAIL", "Webhook returned error", 
                        f"Status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.log("FAIL", "Cannot connect to webhook", 
                    f"URL: {self.webhook_url}")
            return False
        except Exception as e:
            self.log("FAIL", "Webhook test failed", str(e))
            return False
    
    def test_python_modules(self):
        """Test required Python modules"""
        print(f"\n{BLUE}[4] Python Dependencies{RESET}")
        
        modules = ["scapy", "requests"]
        all_ok = True
        
        for module in modules:
            try:
                __import__(module)
                # Get version
                try:
                    version = __import__(module).__version__
                except:
                    version = "installed"
                self.log("PASS", f"Module '{module}' found", f"Version: {version}")
            except ImportError:
                self.log("FAIL", f"Module '{module}' not found", 
                        f"Install: pip install {module}")
                all_ok = False
        
        return all_ok
    
    def test_detector_script(self):
        """Test detector script syntax"""
        print(f"\n{BLUE}[5] Detector Script{RESET}")
        
        script_path = "/home/thunder/fast_detector.py"
        
        # Check file exists
        if not Path(script_path).exists():
            self.log("FAIL", "fast_detector.py not found", f"Path: {script_path}")
            return False
        
        self.log("PASS", "fast_detector.py exists")
        
        # Check syntax
        try:
            result = subprocess.run(
                ["python3", "-m", "py_compile", script_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.log("PASS", "fast_detector.py syntax valid")
            else:
                self.log("FAIL", "Syntax error in fast_detector.py", result.stderr)
                return False
        except Exception as e:
            self.log("FAIL", "Syntax check failed", str(e))
            return False
        
        return True
    
    def test_alert_logger(self):
        """Test alert logger functionality"""
        print(f"\n{BLUE}[6] Alert Logger{RESET}")
        
        try:
            from alert_logger import get_logger
            
            logger = get_logger()
            self.log("PASS", "Alert logger module loads")
            
            # Test log directory
            log_dir = Path("/home/thunder/.n8n/alerts")
            log_dir.mkdir(parents=True, exist_ok=True)
            self.log("PASS", "Alert log directory accessible", str(log_dir))
            
            # Try logging a test alert
            test_alert = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "severity": "LOW",
                "attack_type": "Test",
                "source": "test"
            }
            log_file = logger.log_alert(test_alert)
            self.log("PASS", "Test alert logged successfully", log_file)
            
            return True
        except Exception as e:
            self.log("FAIL", "Alert logger test failed", str(e))
            return False
    
    def test_webhook_alerter(self):
        """Test webhook alerter module"""
        print(f"\n{BLUE}[7] Webhook Alerter Module{RESET}")
        
        try:
            from webhook_alerter import WebhookAlerter
            
            alerter = WebhookAlerter(enabled=False)  # Don't actually send
            self.log("PASS", "Webhook alerter module loads")
            
            # Test configuration
            if alerter.webhook_url:
                self.log("PASS", "Webhook URL configured", alerter.webhook_url)
            
            return True
        except Exception as e:
            self.log("FAIL", "Webhook alerter test failed", str(e))
            return False
    
    def test_config(self):
        """Test configuration module"""
        print(f"\n{BLUE}[8] Configuration Module{RESET}")
        
        try:
            import detector_config as config
            
            self.log("PASS", "Configuration module loads")
            
            # Validate config
            errors = config.validate_config()
            if errors:
                for error in errors:
                    self.log("FAIL", "Config validation error", error)
                return False
            else:
                self.log("PASS", "Configuration is valid")
            
            return True
        except Exception as e:
            self.log("FAIL", "Configuration test failed", str(e))
            return False
    
    def test_network_connectivity(self):
        """Test network connectivity"""
        print(f"\n{BLUE}[9] Network Connectivity{RESET}")
        
        # Test localhost
        try:
            response = requests.get("http://localhost/", timeout=2)
            self.log("PASS", "Localhost is accessible")
        except requests.exceptions.ConnectionError:
            self.log("FAIL", "Cannot connect to localhost", 
                    "Network may be misconfigured")
            return False
        except:
            # Expected - not all hosts have HTTP on localhost
            pass
        
        # Test DNS
        try:
            import socket
            socket.gethostbyname("localhost")
            self.log("PASS", "DNS resolution working")
            return True
        except Exception as e:
            self.log("FAIL", "DNS resolution failed", str(e))
            return False
    
    def test_file_permissions(self):
        """Test file and directory permissions"""
        print(f"\n{BLUE}[10] File Permissions{RESET}")
        
        # Check home directory
        home_dir = Path("/home/thunder")
        if home_dir.exists() and os.access(home_dir, os.W_OK):
            self.log("PASS", "Home directory is writable")
        else:
            self.log("FAIL", "Home directory not writable", str(home_dir))
            return False
        
        # Check .n8n directory
        n8n_dir = Path("/home/thunder/.n8n")
        n8n_dir.mkdir(parents=True, exist_ok=True)
        if os.access(n8n_dir, os.W_OK):
            self.log("PASS", ".n8n directory is writable")
        else:
            self.log("FAIL", ".n8n directory not writable", str(n8n_dir))
            return False
        
        return True
    
    def run_all_tests(self):
        """Run all tests"""
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}WiFi Deauth Defender - System Diagnostics{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        
        tests = [
            ("Docker & n8n", self.test_docker),
            ("n8n Health", self.test_n8n_health),
            ("Webhook Endpoint", self.test_webhook_endpoint),
            ("Python Modules", self.test_python_modules),
            ("Detector Script", self.test_detector_script),
            ("Alert Logger", self.test_alert_logger),
            ("Webhook Alerter", self.test_webhook_alerter),
            ("Configuration", self.test_config),
            ("Network", self.test_network_connectivity),
            ("File Permissions", self.test_file_permissions),
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in tests:
            try:
                result = test_func()
                if result is not False:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                self.log("FAIL", f"{name} - Exception", str(e))
                failed += 1
        
        # Summary
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}Summary{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"Total Tests:  {passed + failed}")
        print(f"{GREEN}Passed:      {passed}{RESET}")
        if failed > 0:
            print(f"{RED}Failed:      {failed}{RESET}")
        
        if failed == 0:
            print(f"\n{GREEN}✓ All tests passed! System is ready.{RESET}")
            return 0
        else:
            print(f"\n{RED}✗ Some tests failed. Please review the output above.{RESET}")
            return 1

def main():
    tester = SystemTester()
    sys.exit(tester.run_all_tests())

if __name__ == "__main__":
    main()

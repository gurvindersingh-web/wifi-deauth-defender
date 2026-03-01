import requests
import time
import sys
from detector_config import N8N_WEBHOOK_URL, AUTH_TOKEN

def watch_connectivity():
    print(f"👀 Watching for n8n connection availability...")
    print(f"🎯 Target: {N8N_WEBHOOK_URL}")
    print("---------------------------------------------------")
    print("ACTION REQUIRED:")
    print("1. Go to your n8n workflow.")
    if "webhook-test" in N8N_WEBHOOK_URL:
        print("2. Click 'Execute Node' (or 'Listen for Event') on the Webhook node.")
    else:
        print("2. Ensure your workflow is set to 'Active'.")
    print("---------------------------------------------------")

    attempt = 1
    while True:
        sys.stdout.write(f"\r⏳ Attempt {attempt}: Pinging n8n... ")
        sys.stdout.flush()
        
        try:
            # Send a neutral "heartbeat" payload
            payload = {
                "severity": "INFO", 
                "attack": "Connectivity Check", 
                "source": "watch_connectivity.py",
                "timestamp": time.time(),
                "message": "Validating n8n connection",
                "packet_rate": 0,
                "details": {}
            }
            
            headers = {
                "X-Auth-Key": AUTH_TOKEN,
                "X-Timestamp": str(int(time.time())),
                "Content-Type": "application/json"
            }
            
            response = requests.post(N8N_WEBHOOK_URL, json=payload, headers=headers, timeout=2)
            
            if response.status_code == 200:
                sys.stdout.write("✅ CONNECTED!\n")
                print("\n🎉 SUCCESS! n8n received the data.")
                print(f"Response: {response.text}")
                break
            elif response.status_code == 403:
                sys.stdout.write("⛔ 403 Forbidden (Waiting for 'Listen' in n8n...)")
            elif response.status_code == 404:
                sys.stdout.write("❌ 404 Not Found (Check URL or Workflow Active status)")
            else:
                sys.stdout.write(f"⚠️ Status {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            sys.stdout.write("❌ Connection Refused (Is n8n running?)")
        except Exception as e:
            sys.stdout.write(f"❌ Error: {e}")
            
        time.sleep(2)
        attempt += 1

if __name__ == "__main__":
    try:
        watch_connectivity()
    except KeyboardInterrupt:
        print("\n\nStopped.")

import time
import json
from collections import defaultdict, deque
from threading import Lock

# ================= CONFIG =================

WINDOW = 30
TRIGGER_THRESHOLD = 5
COOLDOWN = 20
MAX_RISK_SCORE = 10

# Attack weighting (behavior severity)
ATTACK_WEIGHT = {
    "Traffic Flood": 3,
    "Port Scan": 2,
    "UDP Traffic Spike": 2,
    "SYN Probe": 1
}

# ================= STORAGE =================

event_history = defaultdict(deque)
risk_score = defaultdict(int)
last_triggered = {}

lock = Lock()

# ==========================================
# ALERT PROCESSOR
# ==========================================

def process_alert(alert):

    src = alert["source"]
    attack = alert["attack"]
    key = (src, attack)

    current_time = time.time()

    with lock:

        # Maintain sliding time window
        history = event_history[key]
        history.append(current_time)

        while history and current_time - history[0] > WINDOW:
            history.popleft()

        # Update risk score
        risk_score[src] += ATTACK_WEIGHT.get(attack, 1)
        risk_score[src] = min(risk_score[src], MAX_RISK_SCORE)

        # Check cooldown
        if src in last_triggered:
            if current_time - last_triggered[src] < COOLDOWN:
                return

        # Trigger suspicion
        if len(history) >= TRIGGER_THRESHOLD:
            trigger_event(src, attack, len(history))


# ==========================================
# EVENT TRIGGER
# ==========================================

def trigger_event(src, attack, count):

    current_time = time.time()
    last_triggered[src] = current_time

    event = {
        "severity": calculate_severity(src),
        "event": "Suspicious Activity Pattern",
        "source": src,
        "attack_type": attack,
        "occurrences": count,
        "risk_score": risk_score[src],
        "timestamp": current_time,
        "message": "Repeated suspicious behaviour detected"
    }

    print("\n🔥 CORRELATED SECURITY EVENT 🔥")
    print(json.dumps(event, indent=2))


# ==========================================
# SEVERITY CALCULATOR
# ==========================================

def calculate_severity(src):

    score = risk_score[src]

    if score >= 8:
        return "CRITICAL"
    elif score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"

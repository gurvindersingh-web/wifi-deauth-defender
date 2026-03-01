#!/bin/bash

# Antigravity | Premium System Update & Health Protocol
# This script performs system updates, health checks, and state logging.

LOG_FILE="/home/thunder/.n8n/system_updates.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

echo "--------------------------------------------------" | tee -a "$LOG_FILE"
echo "Antigravity Update Protocol Started: $TIMESTAMP" | tee -a "$LOG_FILE"
echo "--------------------------------------------------" | tee -a "$LOG_FILE"

# Step 0: Pre-update State Snapshot
echo "Capturing pre-update system state..." | tee -a "$LOG_FILE"
{
    echo "--- PRE-UPDATE SNAPSHOT ---"
    uname -a
    uptime
    df -h /
    free -h
    echo "--- END SNAPSHOT ---"
} >> "$LOG_FILE"

# Step 1: Update package lists
echo "Updating package lists..." | tee -a "$LOG_FILE"
sudo apt update 2>&1 | tee -a "$LOG_FILE" || { echo "Error updating package lists. Exiting." | tee -a "$LOG_FILE"; exit 1; }

# Step 2: Upgrade installed packages
echo "Upgrading installed packages..." | tee -a "$LOG_FILE"
sudo apt upgrade -y 2>&1 | tee -a "$LOG_FILE" || { echo "Error upgrading packages. Exiting." | tee -a "$LOG_FILE"; exit 1; }

# Step 3: Handle distribution upgrades
echo "Performing distribution upgrade..." | tee -a "$LOG_FILE"
sudo apt dist-upgrade -y 2>&1 | tee -a "$LOG_FILE" || { echo "Error performing distribution upgrade. Exiting." | tee -a "$LOG_FILE"; exit 1; }

# Step 4: Clean up unused packages
echo "Cleaning up unused packages..." | tee -a "$LOG_FILE"
sudo apt autoremove -y 2>&1 | tee -a "$LOG_FILE" || { echo "Error during autoremove. Continuing..." | tee -a "$LOG_FILE"; }

# Step 5: Check for firmware updates
echo -e "\n--- Checking for firmware updates ---" | tee -a "$LOG_FILE"
fwupdmgr get-updates 2>&1 | tee -a "$LOG_FILE"
echo -e "\nTo apply firmware updates, run: sudo fwupdmgr update"

# Step 6: System Health Checks
echo -e "\n--- Performing system health checks ---" | tee -a "$LOG_FILE"

echo -e "\n--- Disk Usage ---" | tee -a "$LOG_FILE"
df -h | tee -a "$LOG_FILE"

echo -e "\n--- Memory Usage ---" | tee -a "$LOG_FILE"
free -h | tee -a "$LOG_FILE"

echo -e "\n--- Recent critical system errors (last boot) ---" | tee -a "$LOG_FILE"
journalctl -p 3 -xb --no-pager | tail -n 20 | tee -a "$LOG_FILE"

echo -e "\nAntigravity system update protocol finished at $(date "+%Y-%m-%d %H:%M:%S")." | tee -a "$LOG_FILE"
echo "Update log saved to: $LOG_FILE"

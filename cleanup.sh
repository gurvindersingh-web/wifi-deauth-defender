#!/bin/bash

echo "===== Ubuntu Cleanup Script Started ====="

# Update package list
echo "[+] Updating package lists..."
sudo apt update

# Remove unused packages
echo "[+] Removing unused packages..."
sudo apt autoremove -y

# Remove old package files from cache
echo "[+] Cleaning package cache..."
sudo apt autoclean -y
sudo apt clean

# Remove old Snap revisions (keeps only latest 2)
echo "[+] Removing old Snap revisions..."
sudo snap set system refresh.retain=2

snap list --all | awk '/disabled/{print $1, $3}' | while read snapname revision; do
    sudo snap remove "$snapname" --revision="$revision"
done

# Remove old journal logs (keep last 7 days)
echo "[+] Cleaning journal logs..."
sudo journalctl --vacuum-time=7d

# Remove thumbnails cache
echo "[+] Cleaning thumbnail cache..."
rm -rf ~/.cache/thumbnails/*

# Remove trash files
echo "[+] Emptying trash..."
rm -rf ~/.local/share/Trash/*

echo "===== Cleanup Completed Successfully ====="

#!/bin/bash
# setup.sh - Quick setup script for Linux Hardener

echo "========================================="
echo "Linux Hardener - Setup Script"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./setup.sh"
    exit 1
fi

# Make script executable
chmod +x linux_hardener.py

# Create symlink (optional)
ln -sf "$(pwd)/linux_hardener.py" /usr/local/bin/linux-hardener

echo "[+] Setup complete!"
echo "[+] Run: sudo linux-hardener"
echo "[+] Or: sudo python3 linux_hardener.py"

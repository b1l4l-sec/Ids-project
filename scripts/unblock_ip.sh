#!/bin/bash
# IP Unblocking Script
# Usage: sudo bash unblock_ip.sh <IP_ADDRESS>

set -e

BLOCKED_LOG="/var/log/honeypot_web/blocked_ips.log"
IP_ADDRESS="$1"

# Input validation
if [ -z "$IP_ADDRESS" ]; then
    echo "Error: No IP address provided"
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

# Validate IP address format
if ! echo "$IP_ADDRESS" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo "Error: Invalid IP address format: $IP_ADDRESS"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Try: sudo $0 $IP_ADDRESS"
    exit 1
fi

# Check if IP is currently blocked
if ! iptables -L INPUT -v -n | grep -q "$IP_ADDRESS"; then
    echo "Warning: IP $IP_ADDRESS does not appear to be blocked"
    echo "Current iptables rules:"
    iptables -L INPUT -v -n | grep DROP | head -5
    exit 0
fi

# Remove the block rule
echo "Unblocking IP: $IP_ADDRESS"
iptables -D INPUT -s "$IP_ADDRESS" -j DROP

if [ $? -eq 0 ]; then
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "✓ Successfully unblocked $IP_ADDRESS"

    # Log the unblock
    mkdir -p "$(dirname "$BLOCKED_LOG")"
    echo "${TIMESTAMP} | UNBLOCKED | ${IP_ADDRESS} | Manual unblock" >> "$BLOCKED_LOG"

    echo "Logged to: $BLOCKED_LOG"
else
    echo "✗ Failed to unblock $IP_ADDRESS"
    echo "You may need to manually remove the rule:"
    echo "  sudo iptables -D INPUT -s $IP_ADDRESS -j DROP"
    exit 1
fi

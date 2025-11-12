#!/bin/bash
# IP Blocking Script
# Usage: sudo bash block_ip.sh <IP_ADDRESS> [REASON]

set -e

BLOCKED_LOG="/var/log/honeypot_web/blocked_ips.log"
IP_ADDRESS="$1"
REASON="${2:-Manual block}"

# Input validation
if [ -z "$IP_ADDRESS" ]; then
    echo "Error: No IP address provided"
    echo "Usage: $0 <IP_ADDRESS> [REASON]"
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

# Safety check: Do not block private/loopback addresses
if [[ "$IP_ADDRESS" =~ ^127\. ]] || \
   [[ "$IP_ADDRESS" =~ ^192\.168\. ]] || \
   [[ "$IP_ADDRESS" =~ ^10\. ]] || \
   [[ "$IP_ADDRESS" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
   [ "$IP_ADDRESS" == "0.0.0.0" ]; then
    echo "Error: Refusing to block private/loopback IP: $IP_ADDRESS"
    echo "This is a safety measure to prevent accidental self-blocking"
    exit 1
fi

# Check if IP is already blocked
if iptables -L INPUT -v -n | grep -q "$IP_ADDRESS"; then
    echo "Warning: IP $IP_ADDRESS may already be blocked"
fi

# Block the IP
echo "Blocking IP: $IP_ADDRESS"
iptables -I INPUT -s "$IP_ADDRESS" -j DROP

if [ $? -eq 0 ]; then
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "✓ Successfully blocked $IP_ADDRESS"

    # Log the block
    mkdir -p "$(dirname "$BLOCKED_LOG")"
    echo "${TIMESTAMP} | BLOCKED | ${IP_ADDRESS} | ${REASON}" >> "$BLOCKED_LOG"

    echo "Logged to: $BLOCKED_LOG"
    echo ""
    echo "To unblock this IP, run:"
    echo "  sudo bash scripts/unblock_ip.sh $IP_ADDRESS"
else
    echo "✗ Failed to block $IP_ADDRESS"
    exit 1
fi

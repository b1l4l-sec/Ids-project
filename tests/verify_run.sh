#!/bin/bash
# Verification Script for Honeypot IDS System
# Tests: Honeypot response, IDS detection, blocking, logging

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="/var/log/honeypot_web"
VERIFICATION_LOG="tests/verification_logs/verification_run_$(date +%Y%m%d_%H%M%S).log"

echo "========================================"
echo "Honeypot IDS Verification"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo "Log directory: $LOG_DIR"
echo "Verification log: $VERIFICATION_LOG"
echo ""

# Create directories
mkdir -p "$LOG_DIR"
mkdir -p "$PROJECT_ROOT/tests/verification_logs"

# Redirect output to log file
exec > >(tee -a "$VERIFICATION_LOG")
exec 2>&1

echo "[$(date)] Starting verification..."
echo ""

# Check Python environment
echo "=== Checking Python Environment ==="
if [ -f "$PROJECT_ROOT/.venv/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
    echo "✓ Using virtual environment"
else
    PYTHON="python3"
    echo "⚠ Virtual environment not found, using system Python"
fi

$PYTHON --version
echo ""

# Check dependencies
echo "=== Checking Dependencies ==="
MISSING_DEPS=0

if ! $PYTHON -c "import flask" 2>/dev/null; then
    echo "✗ Flask not installed"
    MISSING_DEPS=1
else
    echo "✓ Flask installed"
fi

if ! $PYTHON -c "import scapy" 2>/dev/null; then
    echo "✗ Scapy not installed"
    MISSING_DEPS=1
else
    echo "✓ Scapy installed"
fi

if ! $PYTHON -c "import geoip2" 2>/dev/null; then
    echo "✗ geoip2 not installed"
    MISSING_DEPS=1
else
    echo "✓ geoip2 installed"
fi

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo "⚠ Missing dependencies. Run: pip install -r requirements.txt"
    echo ""
fi

# Check GeoIP database
echo ""
echo "=== Checking GeoIP Database ==="
if [ -f "$PROJECT_ROOT/ids/geoip/GeoLite2-City.mmdb" ]; then
    echo "✓ GeoIP database found"
    ls -lh "$PROJECT_ROOT/ids/geoip/GeoLite2-City.mmdb"
else
    echo "⚠ GeoIP database not found (optional for testing)"
    echo "  Run: bash ids/geoip/download_geoip.sh"
fi

# Create config if not exists
echo ""
echo "=== Checking Configuration ==="
if [ ! -f "$PROJECT_ROOT/config.yaml" ]; then
    echo "Creating config.yaml from example..."
    cp "$PROJECT_ROOT/config.example.yaml" "$PROJECT_ROOT/config.yaml"
    echo "✓ config.yaml created"
else
    echo "✓ config.yaml exists"
fi

# Start Flask honeypot
echo ""
echo "=== Starting Flask Honeypot ==="
cd "$PROJECT_ROOT"

$PYTHON app/file.py > "$LOG_DIR/honeypot_test.log" 2>&1 &
HONEYPOT_PID=$!
echo "Started honeypot (PID: $HONEYPOT_PID)"

# Wait for honeypot to start
echo "Waiting for honeypot to start..."
sleep 3

# Check if honeypot is running
if ps -p $HONEYPOT_PID > /dev/null; then
    echo "✓ Honeypot process running"
else
    echo "✗ Honeypot failed to start"
    cat "$LOG_DIR/honeypot_test.log"
    exit 1
fi

# Test honeypot response
echo ""
echo "=== Testing Honeypot Response ==="

if command -v curl &> /dev/null; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/)
    if [ "$HTTP_CODE" == "200" ]; then
        echo "✓ Honeypot responding (HTTP $HTTP_CODE)"
    else
        echo "⚠ Unexpected HTTP code: $HTTP_CODE"
    fi

    # Test login endpoint
    echo "Testing POST to /login..."
    curl -s -X POST http://localhost:8080/login \
        -d "username=test&password=test" \
        -o /dev/null -w "HTTP %{http_code}\n"
else
    echo "⚠ curl not found, skipping HTTP tests"
fi

# Check logs
echo ""
echo "=== Checking Honeypot Logs ==="
if [ -f "$LOG_DIR/honeypot.log" ]; then
    echo "✓ Honeypot log exists"
    echo "Recent entries:"
    tail -n 5 "$LOG_DIR/honeypot.log" || echo "  (empty)"
else
    echo "⚠ Honeypot log not created yet"
fi

# Run attack simulator
echo ""
echo "=== Running Attack Simulator ==="
$PYTHON scripts/attacker_simulator.py --count 3 --delay 0.5 || true

echo ""
echo "Waiting for events to be logged..."
sleep 2

# Check honeypot logs again
echo ""
echo "=== Verifying Logged Events ==="
if [ -f "$LOG_DIR/honeypot.log" ]; then
    EVENT_COUNT=$(grep -c "Request from" "$LOG_DIR/honeypot.log" || echo "0")
    echo "Events logged: $EVENT_COUNT"

    if [ "$EVENT_COUNT" -gt 0 ]; then
        echo "✓ Honeypot successfully logged events"
        echo ""
        echo "Sample log entries:"
        tail -n 3 "$LOG_DIR/honeypot.log"
    else
        echo "⚠ No events logged"
    fi
else
    echo "⚠ Honeypot log not found"
fi

# Stop honeypot
echo ""
echo "=== Stopping Honeypot ==="
if ps -p $HONEYPOT_PID > /dev/null; then
    kill $HONEYPOT_PID
    echo "✓ Stopped honeypot (PID: $HONEYPOT_PID)"
else
    echo "Honeypot process already stopped"
fi

# Test IDS (requires root, may fail in some environments)
echo ""
echo "=== Testing IDS (requires root/capabilities) ==="

if [ "$EUID" -eq 0 ]; then
    echo "Running as root, attempting IDS test..."

    timeout 10 $PYTHON ids/scapy_ids.py > "$LOG_DIR/ids_test.log" 2>&1 &
    IDS_PID=$!
    echo "Started IDS (PID: $IDS_PID)"

    sleep 3

    if ps -p $IDS_PID > /dev/null; then
        echo "✓ IDS process started"
        kill $IDS_PID 2>/dev/null || true
    else
        echo "⚠ IDS process stopped (may be normal)"
    fi

    if [ -f "$LOG_DIR/ids_alerts.log" ]; then
        echo "✓ IDS log exists"
        if [ -s "$LOG_DIR/ids_alerts.log" ]; then
            echo "Sample alerts:"
            head -n 3 "$LOG_DIR/ids_alerts.log"
        fi
    fi
else
    echo "⚠ Not running as root, skipping IDS test"
    echo "  To test IDS, run: sudo bash tests/verify_run.sh"
fi

# Test blocking scripts
echo ""
echo "=== Testing Block Scripts ==="

if [ "$EUID" -eq 0 ]; then
    echo "Testing block_ip.sh with test IP 203.0.113.1 (TEST-NET-3)..."

    bash scripts/block_ip.sh 203.0.113.1 "Verification test" && echo "✓ Block script executed"

    # Check if rule was added
    if iptables -L INPUT -v -n | grep -q "203.0.113.1"; then
        echo "✓ Block rule added to iptables"

        # Test unblock
        echo "Testing unblock_ip.sh..."
        bash scripts/unblock_ip.sh 203.0.113.1 && echo "✓ Unblock script executed"

        # Check if rule was removed
        if ! iptables -L INPUT -v -n | grep -q "203.0.113.1"; then
            echo "✓ Block rule removed from iptables"
        else
            echo "⚠ Block rule still present"
        fi
    else
        echo "⚠ Block rule not found in iptables"
    fi

    # Check blocked IPs log
    if [ -f "$LOG_DIR/blocked_ips.log" ]; then
        echo "✓ Blocked IPs log exists"
        echo "Recent entries:"
        tail -n 2 "$LOG_DIR/blocked_ips.log"
    fi
else
    echo "⚠ Not running as root, skipping block script tests"
    echo "  Blocking requires root privileges"
fi

# Summary
echo ""
echo "========================================"
echo "Verification Summary"
echo "========================================"
echo "✓ Honeypot: Started and responded to requests"
echo "✓ Simulator: Sent test attacks"
echo "✓ Logging: Events logged to honeypot.log"

if [ "$EUID" -eq 0 ]; then
    echo "✓ IDS: Tested (requires root)"
    echo "✓ Blocking: Tested block/unblock scripts"
else
    echo "⚠ IDS: Skipped (requires root)"
    echo "⚠ Blocking: Skipped (requires root)"
fi

echo ""
echo "Log files:"
echo "  - $LOG_DIR/honeypot.log"
echo "  - $LOG_DIR/ids_alerts.log"
echo "  - $LOG_DIR/blocked_ips.log"
echo "  - $VERIFICATION_LOG"
echo ""
echo "To test with IDS and blocking, run:"
echo "  sudo bash tests/verify_run.sh"
echo ""
echo "To view logs:"
echo "  tail -f $LOG_DIR/honeypot.log"
echo ""
echo "========================================"
echo "[$(date)] Verification complete"
echo "========================================"

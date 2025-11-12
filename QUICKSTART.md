# Quick Start Guide

## ⚠️ LEGAL WARNING
**Only run on systems you own. Unauthorized testing is illegal.**

## 5-Minute Setup (Minimal)

```bash
# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv libpcap-dev

# 2. Setup Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Create log directory
sudo mkdir -p /var/log/honeypot_web
sudo chown $USER:$USER /var/log/honeypot_web

# 4. Create config
cp config.example.yaml config.yaml
# Edit config.yaml if needed (defaults work for testing)

# 5. Download GeoIP (requires free MaxMind account)
# Follow instructions from:
bash ids/geoip/download_geoip.sh
# Or skip for testing (code handles missing DB)

# 6. Start honeypot (Terminal 1)
python3 app/file.py

# 7. Start IDS (Terminal 2, requires root)
sudo .venv/bin/python3 ids/scapy_ids.py

# 8. Test it (Terminal 3)
python3 scripts/attacker_simulator.py --count 5

# 9. Check logs
tail -f /var/log/honeypot_web/honeypot.log
tail -f /var/log/honeypot_web/ids_alerts.log
```

## Integration with Existing ELK 8.15

### Logstash Setup

```bash
# Copy pipeline config
sudo cp logstash/logstash_pipeline.conf /etc/logstash/conf.d/honeypot.conf

# Edit to add your Elasticsearch credentials
sudo nano /etc/logstash/conf.d/honeypot.conf
# Uncomment and set: user => "elastic", password => "your_password"

# Restart Logstash
sudo systemctl restart logstash
```

### Kibana Dashboard Import

```bash
# Option 1: Via UI
# 1. Open http://localhost:5601
# 2. Go to Management → Saved Objects → Import
# 3. Select kibana/dashboard_kibana.ndjson
# 4. Import with "Automatically overwrite conflicts"

# Option 2: Via script
cd kibana
bash import_dashboard.sh
```

### Update config.yaml for ELK

```yaml
elk:
  host: "localhost"
  port: 9200
  username: "elastic"
  password: "your_password"

logstash:
  host: "localhost"
  port: 5000
```

## Common Commands

```bash
# Start services
python3 app/file.py                      # Honeypot
sudo python3 ids/scapy_ids.py            # IDS

# Test
python3 scripts/attacker_simulator.py    # Safe local test

# Monitor
tail -f /var/log/honeypot_web/*.log      # All logs
sudo iptables -L INPUT -v -n | grep DROP # Blocked IPs

# Block/unblock manually
sudo bash scripts/block_ip.sh 203.0.113.1 "test"
sudo bash scripts/unblock_ip.sh 203.0.113.1

# Run verification
bash tests/verify_run.sh                 # Without root
sudo bash tests/verify_run.sh            # With root (full test)
```

## Troubleshooting Quick Fixes

### Honeypot won't start
```bash
# Check if port 8080 is in use
sudo netstat -tulpn | grep 8080
# Kill conflicting process or change port in config.yaml
```

### IDS permission denied
```bash
# Grant capabilities (no root needed)
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
python3 ids/scapy_ids.py

# Or run with sudo
sudo .venv/bin/python3 ids/scapy_ids.py
```

### No events in Kibana
```bash
# Check Logstash is running
sudo systemctl status logstash

# Test Logstash connectivity
nc -zv localhost 5000

# Check Elasticsearch has data
curl http://localhost:9200/honeypot-*/_count

# Create index pattern in Kibana: honeypot-*
```

### GeoIP not working
```bash
# Download database (requires free MaxMind account)
# https://www.maxmind.com/en/geolite2/signup
# Place file at: ids/geoip/GeoLite2-City.mmdb

# System works without it (logs warning)
```

## Next Steps

1. Review full README.md for detailed setup
2. Configure SMTP for email alerts (optional)
3. Setup AppArmor profiles (optional)
4. Adjust thresholds in config.yaml
5. Set up log rotation
6. Configure firewall rules
7. Deploy to production

## Support

- Full documentation: README.md
- AppArmor guide: apparmor/README-apparmor.md
- Verification logs: tests/verification_logs/
- Contact: lbienbilal@gmail.com

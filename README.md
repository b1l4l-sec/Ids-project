# IDS Honeypot with AppArmor and ELK Integration

## ⚠️ SAFETY & LEGAL WARNING

**DO NOT run attacker_simulator.py against systems you do not own or have explicit permission to test. Unauthorized access attempts may be illegal under computer fraud and abuse laws. This project is for educational and defensive security purposes only.**

Default simulator target is `localhost`. All attacks are intentionally limited and safe for local testing.

---

## Overview

Full local Proof-of-Concept integrating:
- Flask web honeypot (app/file.py)
- Python IDS using Scapy for network monitoring
- AppArmor confinement profiles
- Integration with **existing ELK 8.15** installation
- GeoIP2 City database for geolocation
- Automated iptables blocking
- Limited attack simulator for testing
- Optional secure email alerting

**IMPORTANT**: This system integrates with your **existing ELK 8.15** installation. It does NOT install or upgrade Elasticsearch/Kibana/Logstash.

---

## System Requirements

- Debian/Ubuntu Linux (tested on Ubuntu 22.04)
- Python 3.10+
- Existing ELK 8.15 installation (Elasticsearch + Kibana + optional Logstash)
- Root/sudo access for AppArmor, iptables, and raw socket sniffing
- Internet connection for GeoIP database download

**Estimated Resource Footprint**:
- Honeypot (Flask): ~50MB RAM
- IDS (Scapy): ~100MB RAM
- Logstash (if used): ~500MB RAM
- Total: ~650MB RAM, minimal CPU when idle

---

## Quick Start

### 1. Install System Dependencies

```bash
# Update package list
sudo apt-get update

# Install Python and network tools
sudo apt-get install -y python3 python3-pip python3-venv \
    libpcap-dev tcpdump apparmor-utils iptables

# Optional: Install Logstash if not already present
# (Skip if you already have Logstash 8.15)
```

### 2. Clone/Extract Repository

```bash
cd /opt
# Extract or clone the repository here
cd ids-honeypot-apparmor-elk
```

### 3. Setup Python Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate environment
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 4. Download GeoIP2 Database

The GeoLite2-City database is required for IP geolocation. Due to MaxMind licensing, you must download it manually:

```bash
# Run the download helper script
cd ids/geoip
bash download_geoip.sh
cd ../..
```

**Manual Steps**:
1. Create free account at https://www.maxmind.com/en/geolite2/signup
2. Generate license key at https://www.maxmind.com/en/accounts/current/license-key
3. Download GeoLite2-City database (MMDB format)
4. Place file at `ids/geoip/GeoLite2-City.mmdb`

Alternative download with license key:
```bash
# Replace YOUR_LICENSE_KEY with your actual key
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" -O GeoLite2-City.tar.gz
tar -xzf GeoLite2-City.tar.gz
mv GeoLite2-City_*/GeoLite2-City.mmdb ids/geoip/
```

### 5. Create Log Directory

```bash
sudo mkdir -p /var/log/honeypot_web
sudo chown $USER:$USER /var/log/honeypot_web
chmod 755 /var/log/honeypot_web
```

### 6. Configure ELK Integration

Copy the example configuration:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` to point to your existing ELK 8.15 endpoints:

```yaml
# Elasticsearch settings
elk:
  host: "localhost"
  port: 9200
  username: "elastic"  # if auth enabled
  password: ""         # set if auth enabled
  use_https: false
  verify_ssl: false
  index_prefix: "honeypot"

# Kibana settings
kibana:
  host: "localhost"
  port: 5601
  username: "elastic"
  password: ""

# Logstash settings (if using Logstash pipeline)
logstash:
  host: "localhost"
  port: 5000
  protocol: "tcp"  # or "udp"
```

### 7. Setup Logstash Pipeline (Optional)

If you want to use Logstash for log processing:

```bash
# Copy pipeline configuration to your Logstash config directory
sudo cp logstash/logstash_pipeline.conf /etc/logstash/conf.d/honeypot.conf

# Edit the pipeline to set your Elasticsearch credentials
sudo nano /etc/logstash/conf.d/honeypot.conf

# Restart Logstash
sudo systemctl restart logstash
```

**Note**: The pipeline is configured for ELK 8.15 with ECS compatibility. Adjust authentication settings in the `elasticsearch` output block.

### 8. Import Kibana Dashboard

```bash
# Option 1: Import via Kibana UI
# 1. Open Kibana at http://localhost:5601
# 2. Navigate to Management → Stack Management → Saved Objects
# 3. Click "Import" and select kibana/dashboard_kibana.ndjson
# 4. Confirm import and resolve any conflicts

# Option 2: Import via API (requires curl and jq)
cd kibana
bash import_dashboard.sh
cd ..
```

The dashboard includes:
- Time-series histogram of alerts
- Top source IPs table
- Alert types pie chart
- World map of attack geolocations
- High-risk alerts metric (last 24h)

Expected index pattern: `honeypot-*`

### 9. Configure SMTP for Email Alerts (Optional)

Set environment variables for email alerting:

```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASS="your-app-password"  # Gmail: Create app password in account settings
export ALERT_EMAIL="lbienbilal@gmail.com"
```

For Gmail:
1. Enable 2-Factor Authentication
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use the 16-character app password as SMTP_PASS

Add to `~/.bashrc` for persistence:
```bash
echo 'export SMTP_HOST="smtp.gmail.com"' >> ~/.bashrc
echo 'export SMTP_PORT="587"' >> ~/.bashrc
echo 'export SMTP_USER="your-email@gmail.com"' >> ~/.bashrc
echo 'export SMTP_PASS="your-app-password"' >> ~/.bashrc
echo 'export ALERT_EMAIL="lbienbilal@gmail.com"' >> ~/.bashrc
```

### 10. Setup AppArmor Profiles

```bash
# Copy profiles to AppArmor directory
sudo cp apparmor/profiles/* /etc/apparmor.d/

# Load profiles in complain mode (testing)
sudo aa-complain /etc/apparmor.d/usr.bin.honeypot-flask
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask

sudo aa-complain /etc/apparmor.d/usr.bin.scapy-ids
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.scapy-ids

# Test the services (see "Running Services" section)
# Monitor AppArmor logs: sudo tail -f /var/log/syslog | grep apparmor

# Once tested, enforce profiles
sudo aa-enforce /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-enforce /etc/apparmor.d/usr.bin.scapy-ids
```

See `apparmor/README-apparmor.md` for detailed AppArmor configuration.

---

## Running Services

### Start Services in Order

**Terminal 1 - Flask Honeypot:**
```bash
source .venv/bin/activate
python3 app/file.py
# Runs on http://0.0.0.0:8080
```

**Terminal 2 - Scapy IDS (requires root/capabilities):**
```bash
source .venv/bin/activate
sudo .venv/bin/python3 ids/scapy_ids.py
```

**Alternative: Grant capabilities to avoid sudo:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
# Then run without sudo:
.venv/bin/python3 ids/scapy_ids.py
```

### Binding Honeypot to Port 80/443

By default, the honeypot runs on port 8080 (non-privileged). To bind to port 80:

**Option 1: Using authbind:**
```bash
sudo apt-get install authbind
sudo touch /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80
sudo chown $USER /etc/authbind/byport/80

# Edit app/file.py and change port to 80
authbind --deep python3 app/file.py
```

**Option 2: Using setcap:**
```bash
sudo setcap 'cap_net_bind_service=+ep' .venv/bin/python3
# Edit app/file.py and change port to 80
python3 app/file.py
```

**Option 3: Port forwarding with iptables:**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

### Stop Services

```bash
# Press Ctrl+C in each terminal
# Or find and kill processes:
pkill -f "python3 app/file.py"
sudo pkill -f "python3 ids/scapy_ids.py"
```

---

## Testing the System

### Run Automated Verification

```bash
# Run smoke tests (safe, targets localhost only)
cd tests
sudo bash verify_run.sh
cd ..

# Check logs
tail -f /var/log/honeypot_web/honeypot.log
tail -f /var/log/honeypot_web/ids_alerts.log
tail -f /var/log/honeypot_web/blocked_ips.log
```

### Manual Testing

**Test honeypot response:**
```bash
curl http://localhost:8080/
curl -X POST http://localhost:8080/login -d "username=admin&password=test"
```

**Test IDS with simulated attacks:**
```bash
source .venv/bin/activate
python3 scripts/attacker_simulator.py --target localhost --count 10
```

**Check blocked IPs:**
```bash
sudo iptables -L INPUT -v -n | grep DROP
cat /var/log/honeypot_web/blocked_ips.log
```

**Unblock an IP:**
```bash
sudo bash scripts/unblock_ip.sh 192.168.1.100
```

---

## Configuration Reference

### config.yaml Structure

```yaml
# Honeypot settings
honeypot:
  port: 8080
  host: "0.0.0.0"
  log_file: "/var/log/honeypot_web/honeypot.log"
  max_payload_snippet: 500

# IDS settings
ids:
  interface: "eth0"  # or "any" for all interfaces
  log_file: "/var/log/honeypot_web/ids_alerts.log"
  threshold: 10
  auto_block: true
  max_blocks_per_hour: 5
  scan_window_seconds: 60
  scan_port_threshold: 10

# GeoIP settings
geoip:
  database_path: "ids/geoip/GeoLite2-City.mmdb"

# ELK integration
elk:
  host: "localhost"
  port: 9200
  username: ""
  password: ""
  use_https: false
  verify_ssl: false
  index_prefix: "honeypot"

logstash:
  host: "localhost"
  port: 5000
  protocol: "tcp"

kibana:
  host: "localhost"
  port: 5601

# Email alerting (optional)
email:
  enabled: false  # Set to true and configure SMTP env vars
  smtp_host: "${SMTP_HOST}"
  smtp_port: 587
  smtp_user: "${SMTP_USER}"
  smtp_password: "${SMTP_PASS}"
  alert_to: "${ALERT_EMAIL}"
  alert_on_high_risk: true
```

### Environment Variables

```bash
# SMTP configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
ALERT_EMAIL=lbienbilal@gmail.com

# ELK credentials (if authentication enabled)
ELK_USERNAME=elastic
ELK_PASSWORD=your-password
```

---

## Architecture & Components

### Flask Honeypot (app/file.py)

- Exposes fake login page at `/`
- Accepts login attempts at `/login` (POST)
- Logs all requests with timestamps, source IPs, headers, POST data
- Sends JSON events to Logstash with GeoIP enrichment
- Sanitizes payloads (default 500 byte limit)
- Handles malformed requests gracefully
- Default port: 8080

### Scapy IDS (ids/scapy_ids.py)

Detects:
- **Port scans**: SYN packets from single source across multiple ports
- **SQL injection**: Patterns like `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
- **Path traversal**: `../`, `..\\`, encoded variants
- **Suspicious user agents**: Scanners, bots, unusual clients

**Scoring system**:
- Each suspicious event adds points to source IP score
- Default threshold: 10 points = HIGH_RISK alert
- HIGH_RISK triggers: Log entry, Logstash event, email (if enabled), auto-block (if enabled)

### GeoIP Integration

- Uses MaxMind GeoLite2-City database
- Resolves city, country, coordinates for each source IP
- Gracefully handles missing database (logs warning, continues)
- Enriches all events sent to ELK

### Logstash Pipeline

- Accepts JSON over TCP/UDP (default port 5000)
- Parses honeypot and IDS events
- Outputs to Elasticsearch index `honeypot-YYYY.MM.dd`
- Compatible with ELK 8.15 and ECS format

### Kibana Dashboard

- Pre-configured visualizations for attack monitoring
- Index pattern: `honeypot-*`
- Includes time-series, geo maps, top attackers, alert metrics

### Iptables Blocking

- **block_ip.sh**: Drops packets from malicious IPs
- **unblock_ip.sh**: Removes block rules
- Safety: Never blocks RFC1918 private addresses or loopback
- Rate limiting: Max 5 auto-blocks per hour (configurable)
- Logs all blocks to `/var/log/honeypot_web/blocked_ips.log`

**Persistence**:
```bash
# Save current rules
sudo iptables-save > /etc/iptables/rules.v4

# Or use netfilter-persistent
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

### Attacker Simulator

**SAFETY FEATURES**:
- Defaults to `localhost` target
- Requires explicit `--target` for other IPs
- Limited workload by default (5 SQLi, 10 port probes, 2 traversal)
- 1-second delay between actions
- No actual exploitation attempts
- Does not download or write large files

```bash
# Safe local test
python3 scripts/attacker_simulator.py

# Custom test (careful!)
python3 scripts/attacker_simulator.py --target 192.168.1.100 --count 20 --delay 2
```

---

## Troubleshooting

### Scapy IDS won't start (permission denied)

```bash
# Grant raw socket capabilities
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3

# Or run with sudo
sudo .venv/bin/python3 ids/scapy_ids.py
```

### Honeypot can't bind to port 80

See "Binding Honeypot to Port 80/443" section above.

### GeoIP database missing

Ensure `ids/geoip/GeoLite2-City.mmdb` exists. Run `ids/geoip/download_geoip.sh` for instructions.

### Logstash connection refused

- Verify Logstash is running: `sudo systemctl status logstash`
- Check pipeline config: `/etc/logstash/conf.d/honeypot.conf`
- Test connectivity: `nc -zv localhost 5000`

### No data in Kibana

- Check Elasticsearch indices: `curl http://localhost:9200/_cat/indices?v`
- Verify index pattern `honeypot-*` exists in Kibana
- Check Logstash logs: `sudo journalctl -u logstash -f`

### AppArmor denials

```bash
# Check denials
sudo grep apparmor /var/log/syslog | grep DENIED

# Switch to complain mode for debugging
sudo aa-complain /etc/apparmor.d/usr.bin.honeypot-flask

# Update profile and reload
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask
```

### Email alerts not sending

- Verify SMTP environment variables are set: `echo $SMTP_HOST`
- Test SMTP credentials manually
- Check IDS logs for email errors: `grep -i smtp /var/log/honeypot_web/ids_alerts.log`
- For Gmail: Ensure 2FA enabled and using app password

---

## Security Considerations

1. **Run on isolated networks**: Deploy honeypots on separate VLANs or DMZ
2. **Monitor disk usage**: Rotate logs regularly to prevent disk exhaustion
3. **Review blocked IPs**: Periodically audit `/var/log/honeypot_web/blocked_ips.log`
4. **Update GeoIP database**: Refresh monthly from MaxMind
5. **Secure ELK access**: Use authentication and TLS for production
6. **AppArmor profiles**: Test thoroughly before enforcing in production
7. **SMTP credentials**: Never commit credentials to version control

---

## Performance Tuning

### Low-resource environments

```yaml
# config.yaml adjustments
ids:
  threshold: 5  # Lower for faster blocking
  scan_window_seconds: 30  # Smaller window

honeypot:
  max_payload_snippet: 200  # Reduce log size
```

### High-traffic environments

```yaml
ids:
  threshold: 20  # Reduce false positives
  max_blocks_per_hour: 20  # Allow more blocks
```

---

## Development & Contributing

### Project Structure

```
ids-honeypot-apparmor-elk/
├── app/               # Flask honeypot application
├── ids/               # Scapy IDS and GeoIP database
├── logstash/          # Logstash pipeline configuration
├── kibana/            # Kibana dashboard export
├── apparmor/          # AppArmor confinement profiles
├── scripts/           # Utility scripts (blocking, simulation)
├── tests/             # Verification scripts and logs
├── config/            # Configuration examples
└── requirements.txt   # Python dependencies
```

### Testing changes

```bash
# Run verification suite
cd tests
sudo bash verify_run.sh

# Check logs
tail -f /var/log/honeypot_web/*.log
```

---

## License

See LICENSE file for details.

---

## Credits

Developed for defensive security research and education.

**Contact**: lbienbilal@gmail.com

**Version**: 1.2.1

**Last Updated**: 2025-11-11

don't forget to use this template to load the attacker location : 
PUT _index_template/honeypot_template
{
  "index_patterns": ["honeypot-*"],
  "template": {
    "mappings": {
      "properties": {
        "source": {
          "properties": {
            "geo": {
              "properties": {
                "location": { "type": "geo_point" }
              }
            }
          }
        }
      }
    }
  }
}

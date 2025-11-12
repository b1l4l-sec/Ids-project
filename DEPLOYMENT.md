# Deployment Guide - IDS Honeypot with AppArmor and ELK

## Pre-Deployment Checklist

- [ ] Linux system with root access (Debian/Ubuntu preferred)
- [ ] ELK 8.15 installed and running
- [ ] Python 3.10+ installed
- [ ] Internet connection (for dependencies and GeoIP DB)
- [ ] At least 1GB free RAM
- [ ] Firewall configured appropriately

## Step-by-Step Deployment

### Phase 1: System Preparation (15 minutes)

```bash
# 1. Update system
sudo apt-get update
sudo apt-get upgrade -y

# 2. Install required packages
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    tcpdump \
    apparmor-utils \
    iptables \
    iptables-persistent

# 3. Clone/extract repository
cd /opt
# Extract or git clone the repository here
cd ids-honeypot-apparmor-elk

# 4. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 5. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
pip list
```

### Phase 2: GeoIP Database Setup (10 minutes)

```bash
# 1. Create MaxMind account (if not already done)
# Visit: https://www.maxmind.com/en/geolite2/signup

# 2. Generate license key
# Visit: https://www.maxmind.com/en/accounts/current/license-key

# 3. Download database
cd ids/geoip
LICENSE_KEY='your_license_key_here'
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz" -O /tmp/GeoLite2-City.tar.gz
tar -xzf /tmp/GeoLite2-City.tar.gz -C /tmp
mv /tmp/GeoLite2-City_*/GeoLite2-City.mmdb .
rm -rf /tmp/GeoLite2-City*
cd ../..

# Verify
ls -lh ids/geoip/GeoLite2-City.mmdb
```

### Phase 3: Configuration (10 minutes)

```bash
# 1. Create log directory
sudo mkdir -p /var/log/honeypot_web
sudo chown $USER:$USER /var/log/honeypot_web
chmod 755 /var/log/honeypot_web

# 2. Copy and edit configuration
cp config.example.yaml config.yaml
nano config.yaml

# Edit these settings:
# - elk.host: Your Elasticsearch host (default: localhost)
# - elk.port: Your Elasticsearch port (default: 9200)
# - elk.username/password: If auth enabled
# - logstash.host/port: Your Logstash host (default: localhost:5000)
# - kibana.host/port: Your Kibana host (default: localhost:5601)
# - ids.threshold: Alert threshold (default: 10)
# - ids.auto_block: Enable auto-blocking (default: true)
# - email.enabled: Enable email alerts (default: false)

# 3. Configure SMTP (optional)
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASS="your-app-password"
export ALERT_EMAIL="lbienbilal@gmail.com"

# Add to ~/.bashrc for persistence
echo "export SMTP_HOST='smtp.gmail.com'" >> ~/.bashrc
echo "export SMTP_PORT='587'" >> ~/.bashrc
echo "export SMTP_USER='your-email@gmail.com'" >> ~/.bashrc
echo "export SMTP_PASS='your-app-password'" >> ~/.bashrc
echo "export ALERT_EMAIL='lbienbilal@gmail.com'" >> ~/.bashrc
```

### Phase 4: ELK Integration (15 minutes)

```bash
# 1. Setup Logstash pipeline
sudo cp logstash/logstash_pipeline.conf /etc/logstash/conf.d/honeypot.conf

# 2. Edit pipeline for your Elasticsearch credentials
sudo nano /etc/logstash/conf.d/honeypot.conf
# Uncomment and set:
#   user => "elastic"
#   password => "your_password"
# If using HTTPS:
#   ssl => true
#   cacert => "/path/to/ca.crt"

# 3. Restart Logstash
sudo systemctl restart logstash
sudo systemctl status logstash

# 4. Verify Logstash is listening
nc -zv localhost 5000

# 5. Import Kibana dashboard
cd kibana
export KIBANA_HOST="localhost"
export KIBANA_PORT="5601"
export KIBANA_USER="elastic"     # If auth enabled
export KIBANA_PASS="your_password"
bash import_dashboard.sh
cd ..

# Or manually via UI:
# 1. Open http://localhost:5601
# 2. Management → Saved Objects → Import
# 3. Select kibana/dashboard_kibana.ndjson
# 4. Check "Automatically overwrite conflicts"
# 5. Import

# 6. Create index pattern (if not auto-created)
# In Kibana: Management → Index Patterns → Create
# Pattern: honeypot-*
# Time field: @timestamp
```

### Phase 5: AppArmor Setup (Optional, 10 minutes)

```bash
# 1. Update paths in profiles
sudo cp apparmor/profiles/* /etc/apparmor.d/

# Edit to match your installation path
sudo nano /etc/apparmor.d/usr.bin.honeypot-flask
sudo nano /etc/apparmor.d/usr.bin.scapy-ids
# Change: /opt/ids-honeypot-apparmor-elk/ to your actual path

# 2. Load profiles in complain mode (testing)
sudo aa-complain /etc/apparmor.d/usr.bin.honeypot-flask
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-complain /etc/apparmor.d/usr.bin.scapy-ids
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.scapy-ids

# 3. Verify loaded
sudo aa-status | grep -E 'honeypot|scapy'

# 4. Test and monitor
# Run services (see Phase 6)
# Monitor denials: sudo tail -f /var/log/syslog | grep apparmor

# 5. Enforce after testing (24-48 hours recommended)
sudo aa-enforce /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-enforce /etc/apparmor.d/usr.bin.scapy-ids
```

### Phase 6: Service Startup (5 minutes)

```bash
# Option A: Manual startup (recommended for testing)

# Terminal 1: Flask Honeypot
source .venv/bin/activate
python3 app/file.py
# Should see: Starting Flask honeypot on 0.0.0.0:8080

# Terminal 2: Scapy IDS
source .venv/bin/activate
sudo .venv/bin/python3 ids/scapy_ids.py
# Should see: Starting Scapy IDS

# Option B: Grant capabilities (run IDS without sudo)
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
source .venv/bin/activate
python3 ids/scapy_ids.py

# Option C: Systemd services (for production)
# See "Production Deployment" section below
```

### Phase 7: Testing & Verification (10 minutes)

```bash
# 1. Run automated tests
bash tests/verify_run.sh
# Or with root:
sudo bash tests/verify_run.sh

# 2. Manual testing
# Terminal 3:
source .venv/bin/activate
python3 scripts/attacker_simulator.py --count 5

# 3. Verify honeypot
curl http://localhost:8080/
curl -X POST http://localhost:8080/login -d "username=admin&password=test"

# 4. Check logs
tail -f /var/log/honeypot_web/honeypot.log
tail -f /var/log/honeypot_web/ids_alerts.log
tail -f /var/log/honeypot_web/blocked_ips.log

# 5. Verify ELK integration
# Check Elasticsearch has data:
curl http://localhost:9200/honeypot-*/_count

# Open Kibana dashboard:
# http://localhost:5601/app/dashboards
# Look for: "Honeypot IDS Dashboard"

# 6. Verify blocking (if auto_block enabled)
sudo iptables -L INPUT -v -n | grep DROP

# 7. Test manual blocking
sudo bash scripts/block_ip.sh 203.0.113.1 "Test"
sudo iptables -L INPUT -v -n | grep 203.0.113.1
sudo bash scripts/unblock_ip.sh 203.0.113.1
```

### Phase 8: Production Hardening (20 minutes)

```bash
# 1. Setup systemd services
sudo tee /etc/systemd/system/honeypot-web.service << EOF
[Unit]
Description=Honeypot Web Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/ids-honeypot-apparmor-elk
ExecStart=/opt/ids-honeypot-apparmor-elk/.venv/bin/python3 /opt/ids-honeypot-apparmor-elk/app/file.py
Restart=always
RestartSec=5
Environment="CONFIG_PATH=/opt/ids-honeypot-apparmor-elk/config.yaml"

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/honeypot-ids.service << EOF
[Unit]
Description=Honeypot IDS Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ids-honeypot-apparmor-elk
ExecStart=/opt/ids-honeypot-apparmor-elk/.venv/bin/python3 /opt/ids-honeypot-apparmor-elk/ids/scapy_ids.py
Restart=always
RestartSec=5
Environment="CONFIG_PATH=/opt/ids-honeypot-apparmor-elk/config.yaml"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable honeypot-web
sudo systemctl enable honeypot-ids
sudo systemctl start honeypot-web
sudo systemctl start honeypot-ids

# Verify
sudo systemctl status honeypot-web
sudo systemctl status honeypot-ids

# 2. Setup log rotation
sudo tee /etc/logrotate.d/honeypot << EOF
/var/log/honeypot_web/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 $USER $USER
    sharedscripts
    postrotate
        systemctl reload honeypot-web > /dev/null 2>&1 || true
        systemctl reload honeypot-ids > /dev/null 2>&1 || true
    endscript
}
EOF

# 3. Persist iptables rules
sudo netfilter-persistent save

# 4. Setup firewall
sudo ufw allow 8080/tcp comment 'Honeypot Web'
# Or bind to 80:
sudo ufw allow 80/tcp comment 'Honeypot Web'

# 5. Enable AppArmor enforcement (after testing)
sudo aa-enforce /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-enforce /etc/apparmor.d/usr.bin.scapy-ids

# 6. Schedule GeoIP updates (monthly)
echo "0 3 1 * * /opt/ids-honeypot-apparmor-elk/ids/geoip/download_geoip.sh" | crontab -
```

## Monitoring & Maintenance

### Daily Checks
```bash
# Check service status
sudo systemctl status honeypot-web honeypot-ids

# Review recent alerts
tail -n 50 /var/log/honeypot_web/ids_alerts.log | grep HIGH_RISK

# Check blocked IPs
tail -n 20 /var/log/honeypot_web/blocked_ips.log

# Review Kibana dashboard
# http://localhost:5601/app/dashboards
```

### Weekly Maintenance
```bash
# Review blocked IPs and unblock false positives
cat /var/log/honeypot_web/blocked_ips.log
sudo bash scripts/unblock_ip.sh <IP_if_needed>

# Check log sizes
du -sh /var/log/honeypot_web/

# Review AppArmor denials (if enforced)
sudo grep DENIED /var/log/syslog | grep -E 'honeypot|scapy'
```

### Monthly Tasks
```bash
# Update GeoIP database
cd /opt/ids-honeypot-apparmor-elk/ids/geoip
bash download_geoip.sh

# Update Python dependencies
source /opt/ids-honeypot-apparmor-elk/.venv/bin/activate
pip list --outdated
pip install --upgrade <package_name>

# Review and adjust thresholds
nano /opt/ids-honeypot-apparmor-elk/config.yaml
sudo systemctl restart honeypot-ids
```

## Troubleshooting

See README.md "Troubleshooting" section for common issues.

Quick diagnostics:
```bash
# Check all logs
tail -f /var/log/honeypot_web/*.log

# Verify Logstash connectivity
nc -zv localhost 5000

# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v | grep honeypot

# Test blocking manually
sudo bash scripts/block_ip.sh 203.0.113.1 "Test"
sudo iptables -L INPUT -v -n
sudo bash scripts/unblock_ip.sh 203.0.113.1
```

## Rollback Procedure

If issues occur:
```bash
# 1. Stop services
sudo systemctl stop honeypot-web honeypot-ids

# 2. Remove systemd services
sudo systemctl disable honeypot-web honeypot-ids
sudo rm /etc/systemd/system/honeypot-*.service
sudo systemctl daemon-reload

# 3. Remove blocked IPs
sudo iptables -F INPUT

# 4. Disable AppArmor profiles
sudo aa-disable /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-disable /etc/apparmor.d/usr.bin.scapy-ids

# 5. Remove Logstash pipeline
sudo rm /etc/logstash/conf.d/honeypot.conf
sudo systemctl restart logstash
```

## Support & Contact

- Documentation: README.md, QUICKSTART.md
- AppArmor Guide: apparmor/README-apparmor.md
- Verification Logs: tests/verification_logs/
- Contact: lbienbilal@gmail.com

---

**Deployment Checklist Summary**

- [ ] System packages installed
- [ ] Python environment configured
- [ ] GeoIP database downloaded
- [ ] Configuration file created and edited
- [ ] ELK integration configured
- [ ] Logstash pipeline deployed
- [ ] Kibana dashboard imported
- [ ] AppArmor profiles loaded (optional)
- [ ] Services started and tested
- [ ] Logs verified
- [ ] Blocking tested
- [ ] Systemd services configured (production)
- [ ] Log rotation configured
- [ ] Monitoring dashboard accessible

**Deployment Complete!**

#!/usr/bin/env python3
"""
Scapy-based Network Intrusion Detection System
Detects port scans, SQL injection, path traversal, and suspicious patterns
"""

import os
import sys
import json
import socket
import logging
import re
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Set
import yaml

try:
    from scapy.all import sniff, IP, TCP, Raw, UDP
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    import geoip2.database
except ImportError:
    print("ERROR: geoip2 not installed. Run: pip install geoip2")
    sys.exit(1)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

CONFIG_PATH = os.environ.get('CONFIG_PATH', 'config.yaml')
LOG_DIR = '/var/log/honeypot_web'
LOG_FILE = os.path.join(LOG_DIR, 'ids_alerts.log')

config = {}
geoip_reader = None

ip_scores: Dict[str, int] = defaultdict(int)
ip_ports: Dict[str, Set[int]] = defaultdict(set)
ip_scan_times: Dict[str, datetime] = {}
blocked_ips: Set[str] = set()
block_count_tracker = {'count': 0, 'reset_time': datetime.now()}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

SQL_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
    r"('\s*OR\s*'1'\s*=\s*'1)",
    r"('\s*OR\s*1\s*=\s*1)",
    r"(\bDROP\b.*\bTABLE\b)",
    r"(\bINSERT\b.*\bINTO\b)",
    r"(\bDELETE\b.*\bFROM\b)",
    r"(--\s*$)",
    r"(;\s*DROP\s)",
    r"(\bEXEC\b.*\bxp_)",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.",
    r"%2e%2e",
    r"%252e%252e",
    r"\.\.\\",
]

SUSPICIOUS_USER_AGENTS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'scanner',
    'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget'
]


def load_config():
    global config
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {CONFIG_PATH}")
        else:
            logger.warning(f"Config file not found: {CONFIG_PATH}, using defaults")
            config = get_default_config()
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        config = get_default_config()


def get_default_config():
    return {
        'ids': {
            'interface': 'any',
            'log_file': LOG_FILE,
            'threshold': 10,
            'auto_block': True,
            'max_blocks_per_hour': 5,
            'scan_window_seconds': 60,
            'scan_port_threshold': 10
        },
        'geoip': {
            'database_path': 'ids/geoip/GeoLite2-City.mmdb'
        },
        'logstash': {
            'host': 'localhost',
            'port': 5000,
            'protocol': 'tcp'
        },
        'email': {
            'enabled': False,
            'smtp_host': os.environ.get('SMTP_HOST', ''),
            'smtp_port': int(os.environ.get('SMTP_PORT', 587)),
            'smtp_user': os.environ.get('SMTP_USER', ''),
            'smtp_password': os.environ.get('SMTP_PASS', ''),
            'alert_to': os.environ.get('ALERT_EMAIL', 'lbienbilal@gmail.com'),
            'alert_on_high_risk': True
        }
    }


def init_geoip():
    global geoip_reader
    geoip_path = config.get('geoip', {}).get('database_path', 'ids/geoip/GeoLite2-City.mmdb')
    try:
        if os.path.exists(geoip_path):
            geoip_reader = geoip2.database.Reader(geoip_path)
            logger.info(f"GeoIP database loaded: {geoip_path}")
        else:
            logger.warning(f"GeoIP database not found: {geoip_path}")
    except Exception as e:
        logger.error(f"Error loading GeoIP database: {e}")


def get_geoip_info(ip_address: str) -> dict:
    if not geoip_reader:
        return {'city': 'Unknown', 'country': 'Unknown', 'latitude': None, 'longitude': None}

    try:
        if ip_address.startswith('127.') or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            return {'city': 'Private', 'country': 'Private', 'country_code': 'Private', 'latitude': None, 'longitude': None}

        response = geoip_reader.city(ip_address)
        return {
            'city': response.city.name or 'Unknown',
            'country': response.country.name or 'Unknown',
            'country_code': response.country.iso_code or 'Unknown',
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except Exception:
        return {'city': 'Unknown', 'country': 'Unknown', 'latitude': None, 'longitude': None}


def send_to_logstash(event_data: dict):
    try:
        logstash_config = config.get('logstash', {})
        host = logstash_config.get('host', 'localhost')
        port = logstash_config.get('port', 5000)
        protocol = logstash_config.get('protocol', 'tcp')

        json_data = json.dumps(event_data) + '\n'

        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(json_data.encode('utf-8'))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json_data.encode('utf-8'), (host, port))
            sock.close()

        logger.debug(f"Sent event to Logstash: {host}:{port}")
    except Exception as e:
        logger.error(f"Failed to send to Logstash: {e}")


def send_email_alert(alert_data: dict):
    try:
        email_config = config.get('email', {})

        if not email_config.get('enabled', False):
            logger.debug("Email alerts disabled")
            return

        if not email_config.get('alert_on_high_risk', True):
            return

        smtp_host = email_config.get('smtp_host')
        smtp_port = email_config.get('smtp_port', 587)
        smtp_user = email_config.get('smtp_user')
        smtp_password = email_config.get('smtp_password')
        alert_to = email_config.get('alert_to')

        if not all([smtp_host, smtp_user, smtp_password, alert_to]):
            logger.warning("Email configuration incomplete, skipping email alert")
            return

        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = alert_to
        msg['Subject'] = f"HIGH RISK ALERT: {alert_data.get('alert_type', 'Unknown')} from {alert_data.get('source_ip', 'Unknown')}"

        body = f"""
HIGH RISK SECURITY ALERT

Timestamp: {alert_data.get('timestamp')}
Alert Type: {alert_data.get('alert_type')}
Source IP: {alert_data.get('source_ip')}
Score: {alert_data.get('score')}
Location: {alert_data.get('geoip', {}).get('city', 'Unknown')}, {alert_data.get('geoip', {}).get('country', 'Unknown')}

Details:
{alert_data.get('details', 'No additional details')}

Payload Snippet:
{alert_data.get('payload_snippet', 'N/A')[:500]}

Action Taken: {'IP Blocked' if alert_data.get('blocked', False) else 'Logged Only'}

This is an automated alert from the IDS Honeypot system.
"""

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()

        logger.info(f"Email alert sent to {alert_to}")

    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")


def is_private_ip(ip: str) -> bool:
    if ip.startswith('127.') or ip == 'localhost':
        return True
    if ip.startswith('192.168.'):
        return True
    if ip.startswith('10.'):
        return True
    if ip.startswith('172.'):
        octets = ip.split('.')
        if len(octets) >= 2:
            try:
                if 16 <= int(octets[1]) <= 31:
                    return True
            except ValueError:
                pass
    return False


def can_auto_block() -> bool:
    global block_count_tracker
    now = datetime.now()

    if now - block_count_tracker['reset_time'] > timedelta(hours=1):
        block_count_tracker = {'count': 0, 'reset_time': now}

    max_blocks = config.get('ids', {}).get('max_blocks_per_hour', 5)

    if block_count_tracker['count'] >= max_blocks:
        logger.warning(f"Auto-block rate limit reached ({max_blocks}/hour)")
        return False

    return True


def block_ip(ip: str, reason: str):
    global blocked_ips, block_count_tracker

    if ip in blocked_ips:
        logger.debug(f"IP already blocked: {ip}")
        return

    if is_private_ip(ip):
        logger.warning(f"Refusing to block private IP: {ip}")
        return

    if not can_auto_block():
        logger.warning(f"Rate limit reached, not blocking: {ip}")
        return

    try:
        script_path = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'block_ip.sh')
        result = subprocess.run(
            ['sudo', 'bash', script_path, ip, reason],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            blocked_ips.add(ip)
            block_count_tracker['count'] += 1
            logger.info(f"Blocked IP: {ip} - Reason: {reason}")
        else:
            logger.error(f"Failed to block IP {ip}: {result.stderr}")

    except Exception as e:
        logger.error(f"Error blocking IP {ip}: {e}")


def create_alert(src_ip: str, dst_ip: str, alert_type: str, details: str, payload: str = '', score: int = 0):
    try:
        geoip_info = get_geoip_info(src_ip)

        event_id = f"{alert_type}_{src_ip}_{int(datetime.now().timestamp())}"

        alert_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'ids_alert',
            'event_id': event_id,
            'alert_type': alert_type,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'score': score,
            'details': details,
            'payload_snippet': payload[:500],
            'geoip': geoip_info
        }

        logger.warning(f"ALERT [{alert_type}] from {src_ip} (score: {score}) - {details}")

        send_to_logstash(alert_data)

        if score >= config.get('ids', {}).get('threshold', 10):
            alert_data['severity'] = 'HIGH_RISK'
            logger.critical(f"HIGH RISK ALERT from {src_ip} - Score: {score}")

            send_email_alert(alert_data)

            if config.get('ids', {}).get('auto_block', True):
                block_ip(src_ip, f"{alert_type} - Score: {score}")
                alert_data['blocked'] = True

        return alert_data

    except Exception as e:
        logger.error(f"Error creating alert: {e}")


def detect_port_scan(packet):
    try:
        if not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if packet[TCP].flags & 0x02:
            now = datetime.now()

            if src_ip not in ip_scan_times:
                ip_scan_times[src_ip] = now
                ip_ports[src_ip] = set()

            time_diff = (now - ip_scan_times[src_ip]).total_seconds()
            scan_window = config.get('ids', {}).get('scan_window_seconds', 60)

            if time_diff > scan_window:
                ip_scan_times[src_ip] = now
                ip_ports[src_ip] = set()

            ip_ports[src_ip].add(dst_port)

            scan_threshold = config.get('ids', {}).get('scan_port_threshold', 10)

            if len(ip_ports[src_ip]) >= scan_threshold:
                score = len(ip_ports[src_ip])
                ip_scores[src_ip] += score

                create_alert(
                    src_ip,
                    packet[IP].dst,
                    'PORT_SCAN',
                    f'Scanned {len(ip_ports[src_ip])} ports in {int(time_diff)}s',
                    f'Ports: {sorted(list(ip_ports[src_ip]))[:20]}',
                    ip_scores[src_ip]
                )

                ip_ports[src_ip] = set()

    except Exception as e:
        logger.error(f"Error in port scan detection: {e}")


def detect_sql_injection(packet):
    try:
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

        for pattern in SQL_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                src_ip = packet[IP].src
                ip_scores[src_ip] += 3

                create_alert(
                    src_ip,
                    packet[IP].dst,
                    'SQL_INJECTION',
                    f'SQL injection pattern detected: {pattern}',
                    payload,
                    ip_scores[src_ip]
                )
                break

    except Exception as e:
        logger.error(f"Error in SQL injection detection: {e}")


def detect_path_traversal(packet):
    try:
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                src_ip = packet[IP].src
                ip_scores[src_ip] += 2

                create_alert(
                    src_ip,
                    packet[IP].dst,
                    'PATH_TRAVERSAL',
                    f'Path traversal pattern detected: {pattern}',
                    payload,
                    ip_scores[src_ip]
                )
                break

    except Exception as e:
        logger.error(f"Error in path traversal detection: {e}")


def detect_suspicious_user_agent(packet):
    try:
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

        if 'user-agent:' in payload:
            for suspicious in SUSPICIOUS_USER_AGENTS:
                if suspicious in payload:
                    src_ip = packet[IP].src
                    ip_scores[src_ip] += 1

                    create_alert(
                        src_ip,
                        packet[IP].dst,
                        'SUSPICIOUS_USER_AGENT',
                        f'Suspicious user agent: {suspicious}',
                        payload,
                        ip_scores[src_ip]
                    )
                    break

    except Exception as e:
        logger.error(f"Error in user agent detection: {e}")


def packet_handler(packet):
    try:
        if not packet.haslayer(IP):
            return

        detect_port_scan(packet)
        detect_sql_injection(packet)
        detect_path_traversal(packet)
        detect_suspicious_user_agent(packet)

    except Exception as e:
        logger.error(f"Error in packet handler: {e}")


def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    load_config()
    init_geoip()

    ids_config = config.get('ids', {})
    interface = ids_config.get('interface', 'any')
    threshold = ids_config.get('threshold', 10)
    auto_block = ids_config.get('auto_block', True)

    logger.info("=" * 60)
    logger.info("Starting Scapy IDS")
    logger.info(f"Interface: {interface}")
    logger.info(f"Alert Threshold: {threshold}")
    logger.info(f"Auto-block: {auto_block}")
    logger.info(f"Logs: {LOG_FILE}")
    logger.info("=" * 60)

    try:
        logger.info("Starting packet capture (press Ctrl+C to stop)...")
        sniff(iface=interface if interface != 'any' else None,
              prn=packet_handler,
              store=False)
    except KeyboardInterrupt:
        logger.info("Stopping IDS...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    if os.geteuid() != 0 and not os.path.exists('/.dockerenv'):
        logger.warning("IDS may require root privileges or CAP_NET_RAW capability")
        logger.warning("Run with: sudo python3 ids/scapy_ids.py")
        logger.warning("Or grant capabilities: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")

    main()

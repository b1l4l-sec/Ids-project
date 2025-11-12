#!/usr/bin/env python3
"""
Flask Honeypot Web Application
Logs all access attempts and sends events to Logstash/ELK
"""

import os
import json
import socket
import logging
from datetime import datetime
from typing import Optional
import yaml
import geoip2.database
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

CONFIG_PATH = os.environ.get('CONFIG_PATH', 'config.yaml')
LOG_DIR = '/var/log/honeypot_web'
LOG_FILE = os.path.join(LOG_DIR, 'honeypot.log')
MAX_PAYLOAD_SNIPPET = 500

config = {}
geoip_reader = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


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
        'honeypot': {
            'port': 8080,
            'host': '0.0.0.0',
            'log_file': LOG_FILE,
            'max_payload_snippet': MAX_PAYLOAD_SNIPPET
        },
        'geoip': {
            'database_path': 'ids/geoip/GeoLite2-City.mmdb'
        },
        'logstash': {
            'host': 'localhost',
            'port': 5000,
            'protocol': 'tcp'
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


def log_request(request_obj, response_status: int = 200):
    try:
        src_ip = request_obj.remote_addr or 'Unknown'

        if request_obj.environ.get('HTTP_X_FORWARDED_FOR'):
            src_ip = request_obj.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()

        max_snippet = config.get('honeypot', {}).get('max_payload_snippet', MAX_PAYLOAD_SNIPPET)
        post_data = ''
        if request_obj.method == 'POST':
            try:
                if request_obj.content_type and 'json' in request_obj.content_type:
                    post_data = str(request_obj.get_json(force=True, silent=True))[:max_snippet]
                else:
                    post_data = str(request_obj.form.to_dict())[:max_snippet]
            except Exception:
                post_data = request_obj.get_data(as_text=True)[:max_snippet]

        geoip_info = get_geoip_info(src_ip)

        event_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'honeypot_access',
            'source_ip': src_ip,
            'method': request_obj.method,
            'path': request_obj.path,
            'user_agent': request_obj.headers.get('User-Agent', 'Unknown')[:200],
            'headers': dict(request_obj.headers),
            'post_data_snippet': post_data,
            'response_status': response_status,
            'geoip': geoip_info,
            'host': request_obj.host
        }

        logger.info(f"Request from {src_ip} - {request_obj.method} {request_obj.path} - Status: {response_status}")

        send_to_logstash(event_data)

    except Exception as e:
        logger.error(f"Error logging request: {e}")


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 14px;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #5568d3;
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Admin Portal</h2>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
        </form>
    </div>
</body>
</html>
"""

SUCCESS_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .success-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            text-align: center;
        }
        h2 {
            color: #11998e;
        }
        p {
            color: #555;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="success-container">
        <h2>✓ Login Successful</h2>
        <p>Welcome to the admin portal.</p>
    </div>
</body>
</html>
"""


@app.route('/')
def index():
    try:
        log_request(request)
        return render_template_string(LOGIN_PAGE)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return "Error", 500


@app.route('/login', methods=['POST'])
def login():
    try:
        log_request(request)
        return render_template_string(SUCCESS_PAGE)
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        return "Error", 500


@app.route('/admin')
@app.route('/admin/')
@app.route('/administrator')
@app.route('/wp-admin')
@app.route('/phpmyadmin')
def admin_paths():
    try:
        log_request(request)
        return render_template_string(LOGIN_PAGE)
    except Exception as e:
        logger.error(f"Error in admin route: {e}")
        return "Error", 500


@app.errorhandler(404)
def not_found(e):
    log_request(request, 404)
    return "Not Found", 404


@app.errorhandler(500)
def server_error(e):
    log_request(request, 500)
    return "Internal Server Error", 500


def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    load_config()
    init_geoip()

    honeypot_config = config.get('honeypot', {})
    port = honeypot_config.get('port', 8080)
    host = honeypot_config.get('host', '0.0.0.0')

    logger.info(f"Starting Flask honeypot on {host}:{port}")
    logger.info(f"Logs: {LOG_FILE}")

    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    main()

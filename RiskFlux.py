#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RISKFLUX CMNI
Risk-Driven Continuous Monitoring & Network Intelligence
Enterprise / SOC-grade — Production Ready (2026)
"""

# ========================= IMPORTS ========================= #
import argparse
import requests
import time
import sys
import os
import csv
import getpass
import hashlib
import logging
import ipaddress
import sqlite3
import base64
import random
from datetime import datetime, timedelta
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========================= CONSTANTS ========================= #
FORTIANALYZER_API = "https://fortianalyzer-api.local"
VERIFY_SSL = True
DEFAULT_INTERVAL = 30
TIME_WINDOW = timedelta(hours=24)

DB_FILE = "riskflux_cmni.db"
LOG_FILE = "riskflux_cmni.log"
TOKEN_FILE = ".riskflux.token"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

VERSION = "1.0.0"

# ========================= LOGGING ========================= #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# ========================= ERROR HANDLING ========================= #
class RiskFluxError(SystemExit):
    def __init__(self, code, message, action=None):
        print(f"\n[ERROR {code}] {message}")
        if action:
            print(f"Action: {action}")
        super().__init__(1)

# ========================= CRYPTO ========================= #
def _master_key():
    key = os.getenv("RISKFLUX_MASTER_KEY")
    if not key:
        raise RiskFluxError(
            "E101",
            "RISKFLUX_MASTER_KEY not defined",
            "export RISKFLUX_MASTER_KEY=$(openssl rand -base64 32)"
        )
    return base64.b64decode(key)

def encrypt(data: str) -> bytes:
    aes = AESGCM(_master_key())
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data.encode(), None)

def decrypt(blob: bytes) -> str:
    aes = AESGCM(_master_key())
    return aes.decrypt(blob[:12], blob[12:], None).decode()

# ========================= AUTH ========================= #
def auth_login():
    token = getpass.getpass("Fortinet API Token: ").strip()
    if not token:
        raise RiskFluxError("E102", "Empty API token", "Re-enter a valid token")
    with open(TOKEN_FILE, "wb") as f:
        f.write(encrypt(token))
    print("[OK] Token stored securely (AES-256-GCM)")

def load_headers():
    if not os.path.isfile(TOKEN_FILE):
        raise RiskFluxError(
            "E203",
            "Authentication required",
            "Run: riskflux auth login"
        )
    with open(TOKEN_FILE, "rb") as f:
        token = decrypt(f.read())
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# ========================= DATABASE ========================= #
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            event_type TEXT,
            severity TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            country TEXT,
            asn TEXT,
            isp TEXT,
            action TEXT,
            hash TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_event(e):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events VALUES (
            NULL,?,?,?,?,?,?,?,?,?,?,?
        )
    """, (
        e["timestamp"], e["src_ip"], e["event_type"],
        e["severity"], e["risk_score"], e["risk_level"],
        e["country"], e["asn"], e["isp"],
        e["action"], e["hash"]
    ))
    conn.commit()
    conn.close()

# ========================= RESILIENCE ========================= #
def retry(fn, attempts=5):
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            wait = 2 ** i + random.random()
            logging.warning(f"Retry {i+1}/{attempts}: {e}")
            time.sleep(wait)
    raise RiskFluxError("E204", "Remote API unreachable", "Check network/API status")

# ========================= THREAT INTEL ========================= #
def enrich_ip(ip):
    if not ABUSEIPDB_API_KEY:
        return {"country":"UNK","asn":"UNK","isp":"UNK","abuse_score":0}
    try:
        r = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "country": d.get("countryCode","UNK"),
            "asn": str(d.get("asn","UNK")),
            "isp": d.get("isp","UNK"),
            "abuse_score": d.get("abuseConfidenceScore",0)
        }
    except Exception:
        return {"country":"UNK","asn":"UNK","isp":"UNK","abuse_score":0}

# ========================= RISK ENGINE ========================= #
def calculate_risk(severity, frequency, abuse):
    score = {"Critical":40,"High":30,"Medium":20,"Low":10}.get(severity,5)
    score += min(frequency * 5, 25)
    score += min(abuse * 0.25, 25)

    if score >= 85: level="CRITICAL"
    elif score >= 65: level="HIGH"
    elif score >= 40: level="MEDIUM"
    else: level="LOW"

    return int(score), level

# ========================= CORE ========================= #
EVENT_HISTORY = defaultdict(list)

def classify_event(evt):
    return {
        "brute_force":"Critical",
        "ddos_attempt":"High",
        "unauthorized_access":"Medium"
    }.get(evt,"Low")

def api_get(headers):
    return retry(lambda: requests.get(
        f"{FORTIANALYZER_API}/logs/security-events",
        headers=headers,
        verify=VERIFY_SSL,
        timeout=10
    ).json())

def process_event(log):
    ip = log.get("src_ip")
    evt = log.get("event_type")

    severity = classify_event(evt)
    EVENT_HISTORY[ip].append(datetime.now())
    EVENT_HISTORY[ip] = [
        t for t in EVENT_HISTORY[ip]
        if datetime.now() - t < TIME_WINDOW
    ]

    intel = enrich_ip(ip)
    score, level = calculate_risk(severity, len(EVENT_HISTORY[ip]), intel["abuse_score"])

    raw = f"{ip}{evt}{score}{level}{datetime.now()}"
    event = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": ip,
        "event_type": evt,
        "severity": severity,
        "risk_score": score,
        "risk_level": level,
        "country": intel["country"],
        "asn": intel["asn"],
        "isp": intel["isp"],
        "action": "MONITORED" if level=="LOW" else "SOC_ACTION",
        "hash": hashlib.sha256(raw.encode()).hexdigest()
    }

    save_event(event)
    logging.info(f"{ip} | {evt} | {level} | {score}")

# ========================= COMMANDS ========================= #
def cmd_monitor(args):
    headers = load_headers()

    ips = []
    for entry in args.ips:
        try:
            ips.extend([str(ip) for ip in ipaddress.ip_network(entry, strict=False)])
        except ValueError:
            raise RiskFluxError(
                "E202",
                f"Invalid IP or CIDR: {entry}",
                "Example: 10.0.0.0/24"
            )

    print("RISKFLUX monitoring started (Ctrl+C to stop)")
    try:
        while True:
            for log in api_get(headers):
                if log.get("src_ip") in ips:
                    process_event(log)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped")

def cmd_report(args):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM events")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        raise RiskFluxError("E301", "No events found", "Run monitor first")

    with open(args.output,"w",newline="",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID","Timestamp","IP","Type","Severity",
            "RiskScore","RiskLevel","Country","ASN",
            "ISP","Action","Hash"
        ])
        writer.writerows(rows)

    print(f"[OK] Report generated: {args.output}")

# ========================= CLI ========================= #
def main():
    init_db()

    parser = argparse.ArgumentParser(
        prog="riskflux",
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "RISKFLUX CMNI — Risk-Driven Continuous Monitoring & Network Intelligence\n\n"
            "FUNCTION:\n"
            "  Collect, correlate and analyze network security events,\n"
            "  calculate dynamic risk scores, enrich events with threat\n"
            "  intelligence and generate forensic evidence.\n\n"
            "REQUIRED CREDENTIALS:\n"
            "  - Fortinet API Token  : riskflux auth login\n"
            "  - RISKFLUX_MASTER_KEY : env (base64, 32 bytes)\n"
            "  - ABUSEIPDB_API_KEY   : optional (recommended)\n\n"
            "EXAMPLES:\n"
            "  riskflux auth login\n"
            "  riskflux monitor --ips 10.0.0.0/24\n"
            "  riskflux monitor --ips 192.168.1.10 192.168.1.20 --interval 60\n"
            "  riskflux report --output incident_2026.csv\n"
        )
    )

    parser.add_argument("-v","--version", action="version", version=VERSION)

    sub = parser.add_subparsers(dest="command")

    auth = sub.add_parser("auth", help="Credential management")
    auth.add_argument("action", choices=["login"])

    monitor = sub.add_parser(
        "monitor",
        help="Start continuous monitoring and risk analysis"
    )
    monitor.add_argument("--ips", nargs="+", required=True)
    monitor.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    monitor.set_defaults(func=cmd_monitor)

    report = sub.add_parser(
        "report",
        help="Export forensic report (CSV)"
    )
    report.add_argument("--output", default="riskflux_report.csv")
    report.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if args.command == "auth":
        auth_login()
    elif hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

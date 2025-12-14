#!/usr/bin/env python3
"""
SENTINELPCAP
Enterprise PCAP Forensic Analyzer & PDF Report Generator

Version: 1.2.0
"""

import os
import sys
import subprocess
import hashlib
import argparse
import signal
from datetime import datetime

# =========================
# METADATA / EXIT CODES
# =========================

VERSION = "1.2.0"

EXIT_SUCCESS = 0
EXIT_INVALID_ARGS = 1
EXIT_MISSING_DEP = 2
EXIT_PCAP_ERROR = 3
EXIT_ANALYSIS_ERROR = 4
EXIT_USER_INTERRUPT = 130   # padrão Unix para CTRL+C

# =========================
# LOGGING
# =========================

def info(msg):
    print(f"[INFO] {msg}")

def warn(msg):
    print(f"[WARN] {msg}")

def error(msg, code):
    print(f"[ERROR] {msg}")
    sys.exit(code)

# =========================
# SIGNAL HANDLING (CTRL+C)
# =========================

def handle_sigint(signum, frame):
    print("\n[INTERRUPTED] Execution interrupted by user (CTRL+C).")
    print("[INTERRUPTED] No changes were committed.")
    print("[INTERRUPTED] Exiting safely with code 130.")
    sys.exit(EXIT_USER_INTERRUPT)

signal.signal(signal.SIGINT, handle_sigint)

# =========================
# SYSTEM UTILITIES
# =========================

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        warn(f"Command failed: {cmd}")
        return ""

def command_exists(cmd):
    return bool(run(f"which {cmd}"))

# =========================
# DEPENDENCY MANAGEMENT
# =========================

def ask_permission(question):
    while True:
        ans = input(f"{question} [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no", ""):
            return False

def install_system_package(pkg):
    info(f"Installing system package: {pkg}")
    subprocess.call(f"sudo apt update && sudo apt install -y {pkg}", shell=True)

def install_python_package(pkg):
    info(f"Installing python package: {pkg}")
    subprocess.call(f"pip3 install {pkg}", shell=True)

def check_and_install_dependencies(non_interactive=False):
    missing_sys = []
    missing_py = []

    if not command_exists("tshark"):
        missing_sys.append("tshark")

    try:
        import numpy
    except ImportError:
        missing_py.append("numpy")

    try:
        import reportlab
    except ImportError:
        missing_py.append("reportlab")

    if not missing_sys and not missing_py:
        info("All dependencies satisfied.")
        return

    warn("Missing dependencies detected:")
    if missing_sys:
        warn(f"  System: {', '.join(missing_sys)}")
    if missing_py:
        warn(f"  Python: {', '.join(missing_py)}")

    if non_interactive:
        error(
            "Dependencies missing and --non-interactive enabled. Aborting.",
            EXIT_MISSING_DEP
        )

    if not ask_permission("Install missing dependencies now?"):
        error("Dependency installation aborted by user.", EXIT_MISSING_DEP)

    for pkg in missing_sys:
        install_system_package(pkg)

    for pkg in missing_py:
        install_python_package(pkg)

    info("Dependency installation completed successfully.")

# =========================
# HASH
# =========================

def sha256sum(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

# =========================
# DETECTION ENGINES
# =========================

def detect_beaconing(pcap):
    import numpy as np

    info("Running beaconing detection engine...")
    output = run(
        f"tshark -r {pcap} -T fields -e frame.time_epoch -e ip.dst"
    ).splitlines()

    timeline = {}
    for line in output:
        try:
            ts, ip = line.split("\t")
            timeline.setdefault(ip, []).append(float(ts))
        except ValueError:
            continue

    suspects = []
    for ip, times in timeline.items():
        if len(times) > 10:
            intervals = np.diff(times)
            if np.std(intervals) < 1:
                suspects.append(ip)

    return suspects

def detect_dns_volume(pcap):
    info("Analyzing DNS traffic volume...")
    out = run(f"tshark -r {pcap} -Y dns | wc -l")
    return int(out.strip()) if out.strip().isdigit() else 0

# =========================
# MITRE & RISK ENGINE
# =========================

def map_mitre(beacons, dns_count):
    techniques = []
    if beacons:
        techniques.append("T1071 – Application Layer Protocol (C2 / Beaconing)")
    if dns_count > 500:
        techniques.append("T1046 – Network Service Discovery (DNS Abuse)")
    return techniques

def calculate_risk(beacons, dns_count):
    score = len(beacons) * 25
    if dns_count > 500:
        score += 20
    return min(score, 100)

def risk_level(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

# =========================
# PDF REPORT
# =========================

def generate_pdf(data, output_file):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    info("Generating PDF report...")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = []

    def add(txt):
        elements.append(Paragraph(txt.replace("\n", "<br/>"), styles["BodyText"]))
        elements.append(Spacer(1, 10))

    elements.append(Paragraph("SENTINELPCAP — SOC FORENSIC REPORT", styles["Title"]))
    add(f"""
    PCAP File: {data['file']}<br/>
    Analysis Date: {data['date']}<br/>
    Analyst: {data['analyst']}<br/>
    PCAP SHA256: {data['pcap_hash']}<br/>
    Risk Score: {data['risk']} / 100<br/>
    Impact Level: {data['impact']}
    """)

    doc.build(elements)

# =========================
# CLI
# =========================

def parse_args():
    parser = argparse.ArgumentParser(
        prog="sentinelpcap.py",
        description="Enterprise PCAP Forensic Analyzer & PDF Report Generator",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--output", help="Output PDF file")
    parser.add_argument("--analyst", default="Not informed")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    return parser.parse_args()

# =========================
# MAIN
# =========================

def main():
    args = parse_args()

    try:
        check_and_install_dependencies(args.non_interactive)

        if not args.pcap:
            if args.non_interactive:
                error("Missing required argument --pcap", EXIT_INVALID_ARGS)
            args.pcap = input("Enter PCAP file path: ").strip()

        if not os.path.isfile(args.pcap):
            error("PCAP file not found or unreadable.", EXIT_PCAP_ERROR)

        info("Starting PCAP analysis pipeline...")

        beacons = detect_beaconing(args.pcap)
        dns_count = detect_dns_volume(args.pcap)

        score = calculate_risk(beacons, dns_count)
        impact = risk_level(score)

        data = {
            "file": os.path.basename(args.pcap),
            "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "analyst": args.analyst,
            "pcap_hash": sha256sum(args.pcap),
            "risk": score,
            "impact": impact
        }

        output = args.output or f"SOC_PCAP_Report_{data['file']}.pdf"
        generate_pdf(data, output)

        info(f"Report generated successfully: {output}")
        sys.exit(EXIT_SUCCESS)

    except KeyboardInterrupt:
        handle_sigint(None, None)

    except Exception as e:
        error(f"Unhandled exception: {e}", EXIT_ANALYSIS_ERROR)

if __name__ == "__main__":
    main()

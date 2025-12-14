#!/usr/bin/env python3
"""
VULNATLAS
Unified Vulnerability Intelligence & Risk Mapping Engine

Version: 1.2.0
"""

import os
import sys
import argparse
import subprocess
import signal
import shutil

# ==========================================================
# METADATA / EXIT CODES
# ==========================================================

VERSION = "1.2.0"

EXIT_SUCCESS = 0
EXIT_INVALID_ARGS = 1
EXIT_MISSING_DEP = 2
EXIT_SCAN_ERROR = 3
EXIT_USER_INTERRUPT = 130

# ==========================================================
# LOGGING
# ==========================================================

def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")
def error(msg, code):
    print(f"[ERROR] {msg}")
    sys.exit(code)

# ==========================================================
# CTRL+C HANDLER
# ==========================================================

def handle_sigint(sig, frame):
    print("\n[INTERRUPTED] Operation interrupted by user (CTRL+C).")
    print("[INTERRUPTED] No scan state was persisted.")
    print(f"[INTERRUPTED] Exit code: {EXIT_USER_INTERRUPT}")
    sys.exit(EXIT_USER_INTERRUPT)

signal.signal(signal.SIGINT, handle_sigint)

# ==========================================================
# UTILITIES
# ==========================================================

def command_exists(cmd):
    return shutil.which(cmd) is not None

def run(cmd):
    return subprocess.call(cmd, shell=True)

def ask_permission(question):
    while True:
        ans = input(f"{question} [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no", ""):
            return False

# ==========================================================
# DEPENDENCY MANAGEMENT
# ==========================================================

def check_and_install_dependencies(non_interactive=False):
    missing_sys = []
    missing_py = []

    # System dependencies
    for tool in ["nmap"]:
        if not command_exists(tool):
            missing_sys.append(tool)

    # Python dependencies
    try:
        import requests  # noqa
    except ImportError:
        missing_py.append("requests")

    if not missing_sys and not missing_py:
        info("Environment validation completed. All dependencies satisfied.")
        return

    warn("Missing dependencies detected:")

    if missing_sys:
        warn(f"  System tools: {', '.join(missing_sys)}")
    if missing_py:
        warn(f"  Python libraries: {', '.join(missing_py)}")

    if non_interactive:
        error(
            "Missing dependencies and --non-interactive mode enabled. Aborting.",
            EXIT_MISSING_DEP
        )

    print("""
These components are required to:
- Perform network discovery and service identification
- Query public vulnerability intelligence sources (NVD, CISA, etc.)
""")

    if not ask_permission("Do you want VULNATLAS to install the missing dependencies now?"):
        error("Dependency installation denied by user.", EXIT_MISSING_DEP)

    if missing_sys:
        info("Installing system dependencies...")
        run("sudo apt update")
        for pkg in missing_sys:
            run(f"sudo apt install -y {pkg}")

    if missing_py:
        info("Installing Python dependencies...")
        for pkg in missing_py:
            run(f"pip3 install {pkg}")

    info("Dependency installation completed successfully.")

# ==========================================================
# SCAN ENGINE
# ==========================================================

def run_scan(target, profile):
    info("Initializing scan engine...")
    info(f"Target: {target}")
    info(f"Profile: {profile}")

    if profile == "quick":
        cmd = f"nmap -T4 {target}"
        impact = "Low"
    elif profile == "full":
        cmd = f"nmap -sV -O {target}"
        impact = "Moderate"
    elif profile == "audit":
        cmd = f"nmap -sV -O --script vuln {target}"
        impact = "Moderate to High"
    else:
        error("Invalid scan profile.", EXIT_INVALID_ARGS)

    info(f"Expected operational impact: {impact}")
    ret = run(cmd)

    if ret != 0:
        error(
            "Scan execution failed. Check target reachability or permissions.",
            EXIT_SCAN_ERROR
        )

# ==========================================================
# INTERACTIVE WIZARD
# ==========================================================

def interactive_wizard():
    print("""
[VULNATLAS] Unified Vulnerability Intelligence & Risk Mapping Engine
-------------------------------------------------------------------
This guided mode will walk you through a vulnerability assessment
step by step, reducing configuration errors and ensuring clarity.
""")

    print("Step 1/5 — Define the scan target")
    target = input(
        "Enter target (IP, CIDR or Domain): "
    ).strip()

    if not target:
        error("Target cannot be empty.", EXIT_INVALID_ARGS)

    print("\nStep 2/5 — Select scan profile")
    print("""
  [1] Quick  — Fast exposure check
  [2] Full   — Services and OS fingerprinting
  [3] Audit  — Deep inspection with vulnerability scripts
""")

    opt = input("Select an option [1-3]: ").strip()

    profile_map = {"1": "quick", "2": "full", "3": "audit"}
    profile = profile_map.get(opt)

    if not profile:
        error("Invalid profile selection.", EXIT_INVALID_ARGS)

    print("\nStep 3/5 — Environment validation")
    check_and_install_dependencies(non_interactive=False)

    print("\nStep 4/5 — Review and confirm")
    print(f"""
Target:       {target}
Scan profile: {profile}
Execution:    Local scan only
""")

    if not ask_permission("Do you want to proceed with the scan?"):
        error("Operation aborted by user.", EXIT_USER_INTERRUPT)

    print("\nStep 5/5 — Scan execution")
    run_scan(target, profile)

# ==========================================================
# CLI ARGUMENTS
# ==========================================================

def parse_args():
    parser = argparse.ArgumentParser(
        prog="vulnatlas.py",
        description="Unified Vulnerability Intelligence & Risk Mapping Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Run vulnerability scan against a target"
    )

    scan.add_argument("--target", help="IP, CIDR or domain")
    scan.add_argument(
        "--profile",
        choices=["quick", "full", "audit"],
        default="quick",
        help="Scan profile"
    )
    scan.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable interactive prompts (SOC / CI)"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser.parse_args()

# ==========================================================
# MAIN
# ==========================================================

def main():
    args = parse_args()

    # Guided mode
    if not args.command:
        interactive_wizard()
        info("VULNATLAS execution completed successfully.")
        sys.exit(EXIT_SUCCESS)

    # CLI mode
    check_and_install_dependencies(args.non_interactive)

    if args.command == "scan":
        if not args.target:
            error("Missing required argument --target", EXIT_INVALID_ARGS)
        run_scan(args.target, args.profile)

    info("VULNATLAS execution completed successfully.")
    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()

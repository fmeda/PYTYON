#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetGuard Sentinel - CLI Firewall Manager
Versão: 5.0
Autor: Fabiano
Descrição: SOC Daemon com Threat Intelligence + SIEM + Alertas em tempo real
"""

import argparse
import logging
import logging.handlers
import json
import csv
import os
import hashlib
import subprocess
import requests
import time
import threading
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# =========================
# Configuração de Logging
# =========================
logger = logging.getLogger("netguard")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("netguard.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)

try:
    syslog_handler = logging.handlers.SysLogHandler(address=("127.0.0.1", 514))
    syslog_handler.setFormatter(logging.Formatter("NetGuard: %(message)s"))
    logger.addHandler(syslog_handler)
except Exception as e:
    console.print(f"[red]⚠ Não foi possível conectar ao Syslog: {e}[/red]")

# =========================
# Configuração de APIs
# =========================
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK", "")

# =========================
# Threat Intelligence
# =========================
def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {"ip": ip, "score": "N/A", "source": "AbuseIPDB"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        data = r.json()["data"]
        return {"ip": ip, "score": data["abuseConfidenceScore"], "source": "AbuseIPDB"}
    except Exception as e:
        return {"ip": ip, "score": f"Erro: {e}", "source": "AbuseIPDB"}

def check_virustotal(ip):
    if not VIRUSTOTAL_KEY:
        return {"ip": ip, "score": "N/A", "source": "VirusTotal"}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()["data"]["attributes"]
        score = data["last_analysis_stats"]["malicious"]
        return {"ip": ip, "score": score, "source": "VirusTotal"}
    except Exception as e:
        return {"ip": ip, "score": f"Erro: {e}", "source": "VirusTotal"}

# =========================
# Notificações
# =========================
def notify(message):
    logger.info(f"Alerta enviado: {message}")
    console.print(f"[blue]📢 {message}[/blue]")

    # Telegram
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message})
        except Exception as e:
            logger.error(f"Erro Telegram: {e}")

    # Slack
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": message})
        except Exception as e:
            logger.error(f"Erro Slack: {e}")

    # Teams
    if TEAMS_WEBHOOK:
        try:
            requests.post(TEAMS_WEBHOOK, json={"text": message})
        except Exception as e:
            logger.error(f"Erro Teams: {e}")

# =========================
# Funções principais
# =========================
def scan_ips(ips):
    console.print("[cyan]🔍 Escaneando IPs com Threat Intelligence...[/cyan]")
    incidents = []
    for ip in ips:
        intel_results = [check_abuseipdb(ip), check_virustotal(ip)]
        risk_score = sum(
            int(r["score"]) if str(r["score"]).isdigit() else 0
            for r in intel_results
        )
        if risk_score > 0:
            incident = {"ip": ip, "risk_score": risk_score, "intel": intel_results}
            incidents.append(incident)
            notify(f"⚠ Ameaça detectada em {ip} | Score: {risk_score}")
        else:
            console.print(f"[green]✔ {ip} sem incidentes[/green]")
    return incidents

def block_ips(ips, fw_type="pfsense"):
    console.print("[yellow]⛔ Bloqueando IPs no firewall...[/yellow]")
    for ip in ips:
        logger.info(f"Bloqueio solicitado: {ip} no {fw_type}")
        notify(f"🔒 {ip} bloqueado no {fw_type}")

def generate_report(incidents, format="json", filename=None):
    if not filename:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"

    if format == "json":
        with open(filename, "w") as f:
            json.dump(incidents, f, indent=4)
    elif format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "risk_score"])
            writer.writeheader()
            for i in incidents:
                writer.writerow({"ip": i["ip"], "risk_score": i["risk_score"]})
    elif format == "txt":
        with open(filename, "w") as f:
            for i in incidents:
                f.write(f"IP: {i['ip']} | Score: {i['risk_score']}\n")

    sha256 = hashlib.sha256(open(filename, "rb").read()).hexdigest()
    console.print(f"[green]📄 Relatório salvo em {filename} | SHA256: {sha256}[/green]")
    logger.info(f"Relatório gerado: {filename} | SHA256: {sha256}")
    return filename

def send_to_zabbix(ip, score, server="127.0.0.1", host="NetGuard", key="threat.score"):
    try:
        subprocess.run([
            "zabbix_sender", "-z", server, "-s", host, "-k", key, "-o", str(score)
        ], check=True)
        logger.info(f"Score {score} enviado ao Zabbix para {ip}")
    except Exception as e:
        console.print(f"[red]⚠ Falha ao enviar para Zabbix: {e}[/red]")

def list_incidents(incidents):
    if not incidents:
        console.print("[green]Nenhum incidente detectado[/green]")
        return
    table = Table(title="Incidentes Detectados")
    table.add_column("IP", style="cyan")
    table.add_column("Score", style="yellow")
    for i in incidents:
        table.add_row(i["ip"], str(i["risk_score"]))
    console.print(table)

# =========================
# Modo Daemon
# =========================
def daemon_mode(interval=60):
    console.print("[magenta]⚡ NetGuard Daemon iniciado...[/magenta]")
    while True:
        try:
            # Aqui poderíamos ler IPs de logs (exemplo: Suricata, pfSense, etc.)
            ips_to_check = ["192.168.1.100", "8.8.8.8"]
            incidents = scan_ips(ips_to_check)
            for i in incidents:
                send_to_zabbix(i["ip"], i["risk_score"])
            if incidents:
                generate_report(incidents, "json")
        except Exception as e:
            logger.error(f"Erro no daemon: {e}")
        time.sleep(interval)

# =========================
# CLI
# =========================
def main():
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard Sentinel - CLI Firewall Manager v5.0"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Escanear IPs em busca de ameaças")
    scan_parser.add_argument("--ips", nargs="+", required=True, help="Lista de IPs para escanear")

    block_parser = subparsers.add_parser("block", help="Bloquear IPs no firewall")
    block_parser.add_argument("--ips", nargs="+", required=True, help="Lista de IPs para bloquear")
    block_parser.add_argument("--fw", default="pfsense", choices=["pfsense", "fortigate"], help="Tipo de firewall")

    report_parser = subparsers.add_parser("report", help="Gerar relatório dos incidentes detectados")
    report_parser.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Formato do relatório")

    daemon_parser = subparsers.add_parser("daemon", help="Executar NetGuard em modo contínuo")
    daemon_parser.add_argument("--interval", type=int, default=60, help="Intervalo em segundos entre varreduras")

    args = parser.parse_args()

    if args.command == "scan":
        incidents = scan_ips(args.ips)
        list_incidents(incidents)
        for i in incidents:
            send_to_zabbix(i["ip"], i["risk_score"])
        if incidents:
            generate_report(incidents, "json")

    elif args.command == "block":
        block_ips(args.ips, fw_type=args.fw)

    elif args.command == "report":
        incidents = [{"ip": "192.168.1.100", "risk_score": 90}]
        generate_report(incidents, format=args.format)

    elif args.command == "daemon":
        threading.Thread(target=daemon_mode, args=(args.interval,), daemon=True).start()
        while True:
            time.sleep(1)  # Mantém o processo vivo

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberSec AI Multi-Toolkit v2.0
Autor: Fabiano Aparecido
Descrição:
  - Conjunto avançado de utilitários para Red/Blue Team, SOC e pentest.
  - Integração opcional com OpenAI (assistente), Shodan, VirusTotal.
  - Gera relatórios HTML/PDF, Risk Score, e sugestões IA-driven.
Compatibilidade: Kali Linux, Parrot OS, BlackArch, distros similares.
Uso: python3 cyber_ai_toolkit.py --help
Versão: 2.0
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ----------------------------
# CONFIGURÁVEIS / CONSTANTES
# ----------------------------
APP_NAME = "CyberSec AI Multi-Toolkit"
VERSION = "2.0"
SUPPORTED_DISTROS = ["kali", "parrot", "blackarch", "debian", "ubuntu"]
REQUIRED_SYSTEM_PACKAGES = ["nmap", "whois", "gobuster", "python3-venv"]
REQUIRED_PY_MODULES = [
    "requests",
    "colorama",
    "tabulate",
    "cryptography",
    "matplotlib",
    "jinja2",
    "python_dotenv",
    "keyring",
]
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
CREDENTIAL_STORE_FILE = os.path.expanduser("~/.cyber_ai_toolkit/credentials.bin")
FERNET_KEY_FILE = os.path.expanduser("~/.cyber_ai_toolkit/.fernet_key")

# Logging
LOG_DIR = os.path.expanduser("~/.cyber_ai_toolkit/logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, f"toolkit_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Terminal colors
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _Fake:
        RED = GREEN = YELLOW = CYAN = MAGENTA = RESET = ""
    Fore = Style = _Fake()

# ----------------------------
# UTILITÁRIOS DE SEGURANÇA
# ----------------------------
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

ensure_dir(os.path.dirname(CREDENTIAL_STORE_FILE))
ensure_dir(LOG_DIR)

def generate_fernet_key() -> bytes:
    from cryptography.fernet import Fernet
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            key = f.read()
        return key
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, "wb") as f:
        os.chmod(FERNET_KEY_FILE, 0o600)
        f.write(key)
    return key

FERNET_KEY = generate_fernet_key()

def store_secret(name: str, secret: str):
    """Encrypt and store secrets locally (simple vault)."""
    from cryptography.fernet import Fernet
    key = FERNET_KEY
    f = Fernet(key)
    payload = json.dumps({"name": name, "secret": secret}).encode()
    token = f.encrypt(payload)
    with open(CREDENTIAL_STORE_FILE, "ab") as fh:
        fh.write(token + b"\n")
    logging.info("Secret stored for %s (encrypted).", name)

def list_secrets() -> List[str]:
    from cryptography.fernet import Fernet
    key = FERNET_KEY
    f = Fernet(key)
    names = []
    if not os.path.exists(CREDENTIAL_STORE_FILE):
        return names
    with open(CREDENTIAL_STORE_FILE, "rb") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(f.decrypt(line).decode())
                names.append(obj.get("name"))
            except Exception:
                continue
    return names

def get_secret_by_name(name: str) -> Optional[str]:
    from cryptography.fernet import Fernet
    key = FERNET_KEY
    f = Fernet(key)
    if not os.path.exists(CREDENTIAL_STORE_FILE):
        return None
    with open(CREDENTIAL_STORE_FILE, "rb") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(f.decrypt(line).decode())
                if obj.get("name") == name:
                    return obj.get("secret")
            except Exception:
                continue
    return None

# ----------------------------
# DEPENDENCY PRE-CHECK & INSTALL
# ----------------------------
def run_cmd(cmd: List[str], check: bool = False) -> Tuple[int, str]:
    """Run external command and return (returncode, stdout+stderr)."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        return -1, ""

def apt_install(packages: List[str]):
    if shutil.which("apt") is None:
        print(Fore.YELLOW + "[!] apt not found. Skipping apt installs. Ensure packages exist on your distro.")
        logging.warning("apt not available on this host.")
        return
    print(Fore.CYAN + "[*] Instalando pacotes do sistema (sudo apt)...")
    pkg_str = " ".join(packages)
    try:
        subprocess.check_call(["sudo", "apt", "update"])
        subprocess.check_call(["sudo", "apt", "install", "-y"] + packages)
    except Exception as e:
        print(Fore.RED + f"[!] Falha apt install: {e}. Verifique manualmente.")
        logging.exception("apt install failed.")

def pip_install(mod: str):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", mod])
    except Exception as e:
        print(Fore.RED + f"[!] Falha pip install {mod}: {e}")
        logging.exception("pip install failed for %s", mod)

def precheck_and_install():
    print(Fore.CYAN + f"[*] Verificando dependências do sistema e Python (modo transparente)...")
    # System packages
    missing_sys = []
    for pkg in REQUIRED_SYSTEM_PACKAGES:
        if shutil.which(pkg) is None:
            missing_sys.append(pkg)
    if missing_sys:
        print(Fore.YELLOW + f"[!] Pacotes de sistema ausentes: {', '.join(missing_sys)}")
        apt_install(missing_sys)
    # Python modules
    missing_py = []
    for mod in REQUIRED_PY_MODULES:
        try:
            __import__(mod)
        except ImportError:
            missing_py.append(mod)
    if missing_py:
        print(Fore.YELLOW + f"[!] Módulos Python ausentes: {', '.join(missing_py)}")
        for m in missing_py:
            pip_install(m)
    print(Fore.GREEN + "[+] Pré-check concluído.")

# ----------------------------
# HELPERS: RELATÓRIO / GERAÇÃO HTML
# ----------------------------
def ensure_template_env():
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except Exception:
        pip_install("jinja2")
        from jinja2 import Environment, FileSystemLoader, select_autoescape

    return Environment(loader=FileSystemLoader(searchpath="./templates"), autoescape=select_autoescape(["html", "xml"]))

def save_html_report(report_html: str, outpath: str):
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(report_html)
    print(Fore.GREEN + f"[+] Relatório HTML salvo em: {outpath}")

def html_to_pdf(html_path: str, pdf_path: str):
    # Attempt to use weasyprint if available, otherwise indicate manual conversion
    try:
        import weasyprint
    except Exception:
        print(Fore.YELLOW + "[!] weasyprint não instalado. Instalando...")
        pip_install("weasyprint")
    try:
        import weasyprint
        weasyprint.HTML(html_path).write_pdf(pdf_path)
        print(Fore.GREEN + f"[+] PDF gerado em: {pdf_path}")
    except Exception as e:
        print(Fore.RED + f"[!] Falha ao gerar PDF: {e}. Você pode converter HTML manualmente.")
        logging.exception("PDF generation failed.")

# ----------------------------
# RISK SCORING
# ----------------------------
@dataclass
class HostRisk:
    host: str
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    exposures: List[str] = field(default_factory=list)
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)

def compute_risk_score(host_risk: HostRisk) -> HostRisk:
    """
    Compute a heuristic risk score (0-100).
    Weights (example):
      - Each open critical port (22, 23, 80, 443, 3389, 445) adds weight.
      - Known risky services add weight.
      - Exposures (shodan/vt) add weight.
    """
    base = 0.0
    for p in host_risk.open_ports:
        if p in {22, 23, 445, 3389, 5900}:
            base += 12
            host_risk.reasons.append(f"Porta crítica aberta: {p}")
        elif p in {80, 443}:
            base += 6
            host_risk.reasons.append(f"Porta web: {p}")
        else:
            base += 2
    # services heuristic
    for p, svc in host_risk.services.items():
        svc_lower = svc.lower() if svc else ""
        if "telnet" in svc_lower:
            base += 15
            host_risk.reasons.append("Serviço Telnet detectado")
        if "smb" in svc_lower or "microsoft-ds" in svc_lower:
            base += 20
            host_risk.reasons.append("SMB exposto")
        if "ftp" in svc_lower:
            base += 8
            host_risk.reasons.append("FTP exposto")
    # exposures from external intelligence
    for e in host_risk.exposures:
        base += 15
        host_risk.reasons.append(f"Exposição externa: {e}")
    # normalize
    score = min(round(base, 2), 100.0)
    host_risk.score = score
    return host_risk

# ----------------------------
# INTEGRAÇÕES (OPCIONAIS)
# ----------------------------
class ExternalIntel:
    def __init__(self, shodan_key: Optional[str] = None, vt_key: Optional[str] = None):
        self.shodan_key = shodan_key
        self.vt_key = vt_key

    def shodan_lookup(self, ip: str) -> List[str]:
        if not self.shodan_key:
            return []
        try:
            import requests
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                tags = []
                if data.get("vulns"):
                    tags += list(data.get("vulns").keys())
                if data.get("data"):
                    tags.append(f"Ports:{','.join(str(p['port']) for p in data.get('data', []))}")
                return tags
            return []
        except Exception as e:
            logging.exception("Shodan lookup failed")
            return []

    def vt_lookup(self, ip_or_domain: str) -> List[str]:
        if not self.vt_key:
            return []
        try:
            import requests
            headers = {"x-apikey": self.vt_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                tags = []
                attrs = data.get("data", {}).get("attributes", {})
                if attrs.get("last_analysis_stats"):
                    tags.append("VT:analysis")
                if attrs.get("malicious"):
                    tags.append("VT:malicious")
                return tags
            return []
        except Exception:
            logging.exception("VT lookup failed")
            return []

# ----------------------------
# IA ASSISTENTE (OPCIONAL)
# ----------------------------
class AIAssistant:
    def __init__(self, openai_key: Optional[str] = None):
        self.openai_key = openai_key

    def analyze_scan(self, nmap_output: str) -> str:
        """
        If OpenAI API key provided, send concise prompt and return human-readable suggestions.
        Otherwise perform local heuristics.
        """
        if self.openai_key:
            # Use OpenAI Completion (user must provide API key)
            try:
                import requests
                url = "https://api.openai.com/v1/chat/completions"
                headers = {"Authorization": f"Bearer {self.openai_key}", "Content-Type": "application/json"}
                prompt = (
                    "You are a security analyst assistant. Given the Nmap output below, provide:\n"
                    "1) Top 3 actionable findings (concise).\n"
                    "2) Recommended next steps (tools/commands).\n"
                    "3) Suggested mitigations.\n\n"
                    "Nmap output:\n```\n" + nmap_output[:15000] + "\n```\n"
                )
                payload = {
                    "model": "gpt-4o-mini",  # placeholder; user decides model
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 600,
                    "temperature": 0.0,
                }
                r = requests.post(url, json=payload, headers=headers, timeout=20)
                if r.status_code == 200:
                    j = r.json()
                    return j["choices"][0]["message"]["content"].strip()
                else:
                    logging.error("OpenAI API error: %s %s", r.status_code, r.text)
                    return "IA indisponível (erro API). Fornecendo heurísticas locais."
            except Exception:
                logging.exception("OpenAI request failed")
                return "IA indisponível (erro local). Fornecendo heurísticas locais."
        # Fallback heuristic parser:
        suggestions = []
        if "445/tcp" in nmap_output:
            suggestions.append("SMB exposto => verificar shares, versões e CVEs (Ex.: enum4linux, smbclient).")
        if "22/tcp" in nmap_output:
            suggestions.append("SSH habilitado => verificar versões, chaves fracas e força bruta possível (fail2ban, sshd hardening).")
        if "80/tcp" in nmap_output or "443/tcp" in nmap_output:
            suggestions.append("Serviço Web => rodar nikto, gobuster, verificar headers e vulnerabilidades comuns.")
        if not suggestions:
            suggestions.append("Nenhuma descoberta direta que corresponda a heurísticas simples; revisar saída manualmente.")
        return "\n".join(f"- {s}" for s in suggestions)

# ----------------------------
# FERRAMENTAS: Nmap, Gobuster, Whois, Sublist3r
# ----------------------------
def run_nmap(target: str, extra_args: str = "") -> str:
    cmd = ["nmap", "-sV", "-O", target] + extra_args.split()
    print(Fore.YELLOW + f"[*] Executando: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        out = proc.stdout
    except Exception as e:
        out = f"[ERROR] Nmap execution failed: {e}"
        logging.exception("Nmap failed for %s", target)
    return out

def run_gobuster(target: str, wordlist: str = DEFAULT_WORDLIST) -> str:
    cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]
    print(Fore.YELLOW + f"[*] Executando: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
        out = proc.stdout
    except Exception as e:
        out = f"[ERROR] Gobuster failed: {e}"
        logging.exception("Gobuster failed for %s", target)
    return out

def run_whois(target: str) -> str:
    cmd = ["whois", target]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        return proc.stdout
    except Exception as e:
        logging.exception("Whois failed")
        return f"[ERROR] Whois failed: {e}"

def run_sublist3r(domain: str) -> str:
    # Attempt to run sublist3r if installed, else fallback (simple DNS brute force not included)
    if shutil.which("sublist3r"):
        cmd = ["sublist3r", "-d", domain]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
            return proc.stdout
        except Exception as e:
            logging.exception("Sublist3r failed")
            return f"[ERROR] Sublist3r failed: {e}"
    else:
        return "[WARN] sublist3r não encontrado; instale ou use outra ferramenta."

# ----------------------------
# RELATÓRIO HTML TEMPLATE (básico embutido)
# ----------------------------
REPORT_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Relatório - {{ title }}</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif; margin:20px;}
    h1{color:#2a6f97;}
    pre{background:#f4f4f4;padding:10px;border-radius:6px;overflow:auto;}
    .section{margin-bottom:20px;}
    .score{font-size:1.6em;color:#b02a2a;}
    table{border-collapse:collapse;width:100%;}
    th,td{padding:8px;border:1px solid #ddd;text-align:left;}
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <p>Gerado em: {{ now }}</p>

  <div class="section">
    <h2>Resumo Executivo</h2>
    <p>{{ executive_summary }}</p>
  </div>

  <div class="section">
    <h2>Findings</h2>
    {% for h in hosts %}
      <h3>{{ h.host }} — Score: <span class="score">{{ h.score }}</span></h3>
      <ul>
        {% for r in h.reasons %}<li>{{ r }}</li>{% endfor %}
      </ul>
      <pre>{{ h.raw }}</pre>
    {% endfor %}
  </div>

  <div class="section">
    <h2>IA Suggestions</h2>
    <pre>{{ ai_suggestions }}</pre>
  </div>
</body>
</html>
"""

# ----------------------------
# CLI / Conversational Parser
# ----------------------------
def parse_natural_command(text: str) -> Tuple[str, Dict]:
    """
    Very light natural language parsing to map user intents to actions.
    Returns (action_key, params)
    Supported intents: scan, whois, enum, gobuster, report, list-secrets, store-secret, mode-red, mode-blue
    """
    t = text.lower().strip()
    # scan range or host
    m = re.search(r"(scan|scannear|varredura).*?(\d+\.\d+\.\d+\.\d+(?:/\d+)?|\S+\.\S+)", t)
    if m:
        target = m.group(2)
        return "scan", {"target": target}
    # whois
    m = re.search(r"(whois|consulta whois|domínio).*?(\S+\.\S+)", t)
    if m:
        return "whois", {"target": m.group(2)}
    # subdomain
    if "subdom" in t or "subdomain" in t or "sublista" in t:
        m = re.search(r"(\S+\.\S+)", t)
        return "subenum", {"domain": m.group(1) if m else ""}
    # gobuster
    if "gobuster" in t or "directório" in t or "dir" in t:
        m = re.search(r"(http[s]?://\S+)", t)
        return "gobuster", {"target": m.group(1) if m else ""}
    # report
    if "report" in t or "relat" in t:
        return "report", {}
    # store secret
    if "store" in t or "guardar" in t or "salvar chave" in t:
        m = re.search(r"(\w+)\s+(.+)$", t)
        return "store-secret", {"name": m.group(1) if m else "key", "secret": m.group(2) if m else ""}
    # list secrets
    if "list" in t and ("secret" in t or "chave" in t):
        return "list-secrets", {}
    # fallback
    return "unknown", {}

# ----------------------------
# INTERFACE PRINCIPAL E MENUS
# ----------------------------
class Toolkit:
    def __init__(self, args):
        self.args = args
        self.mode = args.mode or "mixed"
        self.external = ExternalIntel(shodan_key=args.shodan_key, vt_key=args.vt_key)
        self.ai = AIAssistant(openai_key=args.openai_key)
        self.history = []

    def banner(self):
        print(Fore.GREEN + Style.BRIGHT + f"{APP_NAME} — v{VERSION}")
        print(Fore.CYAN + "Modo: " + Fore.YELLOW + (self.mode.upper()))

    def interactive_shell(self):
        self.banner()
        print(Fore.CYAN + "Digite comandos (ex.: 'scan 10.0.0.1', 'whois example.com', 'relatório'). 'sair' para sair.")
        while True:
            try:
                cmd = input(Fore.CYAN + "\ncyber> ").strip()
            except (KeyboardInterrupt, EOFError):
                print(Fore.RED + "\n[!] Interrompido. Saindo.")
                break
            if not cmd:
                continue
            if cmd.lower() in {"sair", "exit", "quit", "q"}:
                print(Fore.GREEN + "[+] Saindo. Até logo.")
                break
            action, params = parse_natural_command(cmd)
            self.execute_action(action, params, raw_cmd=cmd)

    def execute_action(self, action: str, params: Dict, raw_cmd: str = ""):
        if action == "scan":
            target = params.get("target") or raw_cmd.split()[-1]
            self.run_scan_flow(target)
        elif action == "whois":
            target = params.get("target")
            out = run_whois(target)
            print(out)
            self.history.append(("whois", target, out))
        elif action == "subenum":
            domain = params.get("domain")
            out = run_sublist3r(domain)
            print(out)
            self.history.append(("subenum", domain, out))
        elif action == "gobuster":
            target = params.get("target")
            out = run_gobuster(target)
            print(out)
            self.history.append(("gobuster", target, out))
        elif action == "report":
            self.generate_report()
        elif action == "store-secret":
            name = params.get("name") or input("Nome da chave: ")
            secret = params.get("secret") or getpass.getpass("Segredo: ")
            store_secret(name, secret)
            print(Fore.GREEN + "[+] Segredo armazenado (encrypted).")
        elif action == "list-secrets":
            s = list_secrets()
            print("Stored:", s)
        else:
            print(Fore.YELLOW + "[!] Comando desconhecido — tentarei interpretar usando IA se disponível.")
            # try to map using AI (if key present)
            if self.ai.openai_key:
                suggestion = self.ai.analyze_scan(raw_cmd)
                print(Fore.CYAN + "[IA] Sugestão:\n" + suggestion)
            else:
                print("Use comandos como: 'scan 10.0.0.1', 'whois example.com', 'gobuster http://target'")

    def run_scan_flow(self, target: str):
        print(Fore.CYAN + f"[*] Iniciando workflow para: {target}")
        nmap_out = run_nmap(target)
        print(nmap_out[:800] + ("\n...[truncated]" if len(nmap_out) > 800 else ""))
        # parse open ports (lightweight parsing)
        open_ports = []
        services = {}
        for line in nmap_out.splitlines():
            m = re.search(r"^(\d+)\/tcp\s+open\s+([\w\-\_\/\.]+)", line)
            if m:
                p = int(m.group(1))
                s = m.group(2)
                open_ports.append(p)
                services[p] = s
        host_risk = HostRisk(host=target, open_ports=open_ports, services=services)
        # external intel
        exposures = []
        if self.external.shodan_key:
            exposures += self.external.shodan_lookup(target)
        if self.external.vt_key:
            exposures += self.external.vt_lookup(target)
        host_risk.exposures = exposures
        host_risk = compute_risk_score(host_risk)
        # AI analyze
        ai_suggest = self.ai.analyze_scan(nmap_out)
        # save to history
        self.history.append(("scan", target, {"nmap": nmap_out, "risk": host_risk, "ai": ai_suggest}))
        # Present summary
        print(Fore.MAGENTA + f"\n[RESULT] Host: {target} — Risk Score: {host_risk.score}/100")
        for r in host_risk.reasons:
            print(Fore.YELLOW + f" - {r}")
        print(Fore.CYAN + "\n[IA] Insights:\n" + ai_suggest)

    def generate_report(self, outdir: Optional[str] = None):
        ensure_dir(outdir or os.getcwd())
        title = f"Relatório {APP_NAME}"
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        # create hosts list
        hosts = []
        for item in self.history:
            if item[0] == "scan":
                target = item[1]
                details = item[2]
                hr: HostRisk = details["risk"]
                hosts.append({
                    "host": hr.host,
                    "score": hr.score,
                    "reasons": hr.reasons,
                    "raw": (details["nmap"][:4000] + ("\n...[truncated]" if len(details["nmap"]) > 4000 else "")),
                })
        # AI summary (concat minor)
        ai_all = "\n\n".join(item[2]["ai"] if item[0] == "scan" else "" for item in self.history)
        # simple exec summary
        exec_summary = f"Relatório gerado automaticamente. {len(hosts)} host(s) analisado(s). Modo: {self.mode}."
        # render template
        try:
            from jinja2 import Template
            tmpl = Template(REPORT_TEMPLATE)
            report_html = tmpl.render(title=title, now=now, executive_summary=exec_summary, hosts=hosts, ai_suggestions=ai_all or "Nenhuma sugestão IA disponível.")
            outpath = os.path.join(outdir or os.getcwd(), f"report_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.html")
            save_html_report(report_html, outpath)
            # attempt PDF
            pdf_out = outpath.replace(".html", ".pdf")
            html_to_pdf(outpath, pdf_out)
        except Exception:
            logging.exception("Report generation failed.")
            print(Fore.RED + "[!] Falha ao gerar relatório. Verifique dependências.")

# ----------------------------
# ARGPARSE & MAIN
# ----------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(prog="cyber_ai_toolkit", description="CyberSec AI Multi-Toolkit")
    p.add_argument("--mode", choices=["red", "blue", "mixed"], help="Modo de operação (red/blue/mixed).")
    p.add_argument("--shodan-key", help="Chave API Shodan (opcional).")
    p.add_argument("--vt-key", help="Chave API VirusTotal (opcional).")
    p.add_argument("--openai-key", help="Chave API OpenAI (opcional).")
    p.add_argument("--precheck", action="store_true", help="Executar pré-check de dependências.")
    p.add_argument("--nogui", action="store_true", help="Modo não interativo (batch).")
    return p

def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.precheck:
        precheck_and_install()
    toolkit = Toolkit(args)
    if args.nogui:
        # Example batch run for demo (user likely customizes)
        print(Fore.CYAN + "[*] Executando modo batch demo (nogui).")
        # Try scanning a sample host placeholder (user should pass command in real use)
        demo_target = "127.0.0.1"
        toolkit.run_scan_flow(demo_target)
        toolkit.generate_report()
    else:
        toolkit.interactive_shell()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrompido pelo usuário. Encerrando.")
        sys.exit(0)

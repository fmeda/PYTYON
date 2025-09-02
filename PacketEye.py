#!/usr/bin/env python3
"""
PacketEye - Network Troubleshooting CLI com Logging JSON
Autor: Fabiano Aparecido
Descrição: CLI interativa de troubleshooting de rede com logs estruturados.
"""

import os
import sys
import subprocess
import signal
import importlib.util
import socket
import platform
import json
from datetime import datetime

# ===============================
# Pré-check de módulos
# ===============================
REQUIRED_MODULES = ["cmd2", "psutil"]

def install_missing_modules():
    """Instala módulos Python ausentes automaticamente"""
    for module in REQUIRED_MODULES:
        if importlib.util.find_spec(module) is None:
            print(f"[INFO] Instalando módulo ausente: {module}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules()

import cmd2
import psutil

# ===============================
# Configurações globais
# ===============================
LOG_FILE = "PacketEye_log.json"

def log_event(action, target=None, port=None, status=None, output=None):
    """Registra evento em arquivo JSON"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "target": target,
        "port": port,
        "status": status,
        "output": output
    }
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []
        logs.append(entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"[WARN] Não foi possível salvar log: {e}")

# ===============================
# Tratamento de CTRL+C
# ===============================
def handle_sigint(sig, frame):
    print("\n[!] Encerrando PacketEye CLI. Até logo!")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

# ===============================
# Funções de diagnóstico
# ===============================
def ping_host(host="8.8.8.8"):
    """Executa ping e retorna saída"""
    print(f"[INFO] Executando ping para {host}...\n")
    try:
        cmd = ["ping", "-c", "4", host] if platform.system() != "Windows" else ["ping", host]
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        print(output)
        log_event("ping", target=host, status="success", output=output)
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao pingar {host}")
        log_event("ping", target=host, status="fail", output=str(e))

def traceroute_host(host="8.8.8.8"):
    """Executa traceroute/tracert"""
    print(f"[INFO] Executando traceroute para {host}...\n")
    try:
        cmd = ["traceroute", host] if platform.system() != "Windows" else ["tracert", host]
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        print(output)
        log_event("traceroute", target=host, status="success", output=output)
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao traceroute {host}")
        log_event("traceroute", target=host, status="fail", output=str(e))

def listar_interfaces():
    """Lista interfaces de rede"""
    print("[INFO] Listando interfaces de rede disponíveis:\n")
    for iface, addrs in psutil.net_if_addrs().items():
        print(f"Interface: {iface}")
        for addr in addrs:
            print(f"  {addr.family}: {addr.address}")
        print("-" * 40)
    log_event("interfaces", status="success")

def verificar_porta(host="127.0.0.1", porta=22):
    """Verifica se porta TCP está aberta"""
    print(f"[INFO] Verificando porta {porta} em {host}...\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex((host, porta))
        if result == 0:
            print(f"[OK] Porta {porta} aberta em {host}")
            log_event("portscan", target=host, port=porta, status="open")
        else:
            print(f"[X] Porta {porta} fechada ou inacessível em {host}")
            log_event("portscan", target=host, port=porta, status="closed")
    except Exception as e:
        print(f"[ERRO] Falha ao verificar porta: {e}")
        log_event("portscan", target=host, port=porta, status="error", output=str(e))
    finally:
        sock.close()

# ===============================
# Classe CLI Interativa
# ===============================
class PacketEyeCLI(cmd2.Cmd):
    prompt = "(PacketEye) "
    intro = "Bem-vindo à PacketEye CLI! Digite 'help' para opções."

    def do_ping(self, arg):
        """Ping a um host: ping <host>"""
        host = arg.strip() if arg else "8.8.8.8"
        ping_host(host)

    def do_traceroute(self, arg):
        """Traceroute até um host: traceroute <host>"""
        host = arg.strip() if arg else "8.8.8.8"
        traceroute_host(host)

    def do_interfaces(self, arg):
        """Lista interfaces de rede"""
        listar_interfaces()

    def do_portscan(self, arg):
        """Verifica porta TCP: portscan <host> <porta>"""
        try:
            host, port = arg.split()
            verificar_porta(host, int(port))
        except ValueError:
            print("[ERRO] Uso correto: portscan <host> <porta>")

    def do_exit(self, arg):
        """Sai da CLI"""
        print("Encerrando PacketEye CLI... Até logo!")
        return True

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    cli = PacketEyeCLI()
    cli.cmdloop()

#!/usr/bin/env python3
"""
PacketEye CMNI - Network Intelligence & Troubleshooting CLI
Autor: Fabiano Aparecido
Descrição: Ferramenta CLI avançada com análise CMNI, métricas detalhadas, correlação de eventos, alertas inteligentes e relatórios estratégicos.
"""

import os, sys, subprocess, signal, importlib.util, socket, platform, json, getpass, uuid, csv, statistics
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import psutil
import cmd2
from tabulate import tabulate

# ===============================
# Pré-check de módulos
# ===============================
REQUIRED_MODULES = ["cmd2", "psutil", "tabulate"]

def install_missing_modules():
    for module in REQUIRED_MODULES:
        if importlib.util.find_spec(module) is None:
            print(f"[INFO] Instalando módulo ausente: {module}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules()
from tabulate import tabulate

# ===============================
# Configurações globais
# ===============================
LOG_FILE = "PacketEye_CMNI_log.json"
REPORT_CSV = "PacketEye_CMNI_report.csv"
USERS = {"admin": "admin123"}
CRITICAL_PORTS = [22, 80, 443]

# ===============================
# Logs Avançados com Inteligência
# ===============================
def log_event(user, action, target=None, port=None, status=None, output=None, tags=None, severity="INFO"):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action_id": str(uuid.uuid4()),
        "action": action,
        "target": target,
        "port": port,
        "status": status,
        "output": output,
        "tags": tags or [],
        "severity": severity
    }
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        logs.append(entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"[WARN] Não foi possível salvar log: {e}")

def export_report_csv():
    if not os.path.exists(LOG_FILE):
        print("[WARN] Nenhum log para gerar relatório.")
        return
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
    with open(REPORT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    print(f"[OK] Relatório CSV gerado: {REPORT_CSV}")

def analyze_cmni():
    """Analisa os logs e gera insights inteligentes de maturidade de rede"""
    if not os.path.exists(LOG_FILE):
        print("[WARN] Nenhum log disponível para análise CMNI.")
        return
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
    
    ping_rtts = []
    port_failures = {}
    
    for entry in logs:
        if entry["action"] == "ping" and entry["status"] == "success":
            # Extrai RTT médio do ping
            lines = entry["output"].splitlines()
            for l in lines:
                if "time=" in l:
                    try:
                        time_ms = float(l.split("time=")[1].split(" ")[0])
                        ping_rtts.append(time_ms)
                    except: pass
        if entry["action"] == "portscan" and entry["status"] != "open":
            port_failures[entry["port"]] = port_failures.get(entry["port"], 0) + 1

    print("\n=== CMNI Insights ===")
    if ping_rtts:
        print(f"- Latência média de ping: {statistics.mean(ping_rtts):.2f} ms")
        print(f"- Latência mínima: {min(ping_rtts):.2f} ms, máxima: {max(ping_rtts):.2f} ms")
    if port_failures:
        print("- Portas com falhas frequentes:")
        for port, count in port_failures.items():
            print(f"  Porta {port}: {count} falhas")
    print("- Total de eventos registrados:", len(logs))
    print("====================\n")

# ===============================
# Tratamento de CTRL+C
# ===============================
def handle_sigint(sig, frame):
    print("\n[!] Encerrando PacketEye CMNI. Até logo!")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

# ===============================
# Autenticação CLI
# ===============================
def authenticate():
    print("=== Autenticação PacketEye CMNI ===")
    username = input("Usuário: ")
    password = getpass.getpass("Senha: ")
    if USERS.get(username) == password:
        print(f"[OK] Autenticado como {username}")
        return username
    print("[ERRO] Usuário ou senha incorretos")
    sys.exit(1)

# ===============================
# Funções Avançadas de Diagnóstico
# ===============================
def ping_host(user, host="8.8.8.8", count=4):
    print(f"[INFO] Ping para {host}...")
    cmd = ["ping", "-c", str(count), host] if platform.system() != "Windows" else ["ping", "-n", str(count), host]
    try:
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        print(output)
        log_event(user, "ping", target=host, status="success", output=output, tags=["network","CMNI"])
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao pingar {host}")
        log_event(user, "ping", target=host, status="fail", output=str(e), severity="ERROR")

def traceroute_host(user, host="8.8.8.8"):
    print(f"[INFO] Traceroute para {host}...")
    cmd = ["traceroute", host] if platform.system() != "Windows" else ["tracert", host]
    try:
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        print(output)
        log_event(user, "traceroute", target=host, status="success", output=output, tags=["network"])
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao traceroute {host}")
        log_event(user, "traceroute", target=host, status="fail", output=str(e), severity="ERROR")

def listar_interfaces(user):
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = {"Interface": iface}
        for addr in addrs:
            iface_info[f"{addr.family}"] = addr.address
        interfaces.append(iface_info)
    print(tabulate(interfaces, headers="keys"))
    log_event(user, "interfaces", status="success", output=str(interfaces), tags=["network"])

def verificar_portas(user, host="127.0.0.1", ports=None):
    ports = ports or CRITICAL_PORTS
    results = []

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((host, port))
            status = "open" if result == 0 else "closed"
            log_event(user, "portscan", target=host, port=port, status=status)
            return (port, status)
        except Exception as e:
            log_event(user, "portscan", target=host, port=port, status="error", output=str(e), severity="ERROR")
            return (port, "error")
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, port) for port in ports]
        for f in futures:
            results.append(f.result())

    print(tabulate(results, headers=["Porta", "Status"]))

def discover_hosts(user, base_ip="192.168.1.", start=1, end=254):
    print(f"[INFO] Descobrindo hosts ativos em {base_ip}0/24...")
    active_hosts = []

    def ping_ip(i):
        ip = f"{base_ip}{i}"
        try:
            cmd = ["ping", "-c", "1", ip] if platform.system() != "Windows" else ["ping", "-n", "1", ip]
            subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            log_event(user, "host_discovery", target=ip, status="active")
            active_hosts.append(ip)
        except: pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping_ip, range(start, end + 1))

    print("[INFO] Hosts ativos encontrados:")
    for host in active_hosts:
        print(f" - {host}")

# ===============================
# CLI Interativa
# ===============================
class PacketEyeCMNICLI(cmd2.Cmd):
    prompt = "(PacketEyeCMNI) "
    intro = "Bem-vindo à PacketEye CMNI CLI! Digite 'help' para opções."

    def __init__(self, user):
        super().__init__()
        self.user = user

    # Comandos
    def do_ping(self, arg):
        host = arg.strip() if arg else "8.8.8.8"
        ping_host(self.user, host)

    def do_traceroute(self, arg):
        host = arg.strip() if arg else "8.8.8.8"
        traceroute_host(self.user, host)

    def do_interfaces(self, arg):
        listar_interfaces(self.user)

    def do_portscan(self, arg):
        args = arg.split()
        host = args[0] if args else "127.0.0.1"
        ports = list(map(int, args[1:])) if len(args) > 1 else None
        verificar_portas(self.user, host, ports)

    def do_discover(self, arg):
        base_ip = arg.strip() if arg else "192.168.1."
        discover_hosts(self.user, base_ip)

    def do_report(self, arg):
        export_report_csv()

    def do_cmni(self, arg):
        """Executa análise CMNI dos logs"""
        analyze_cmni()

    def do_exit(self, arg):
        print("Encerrando PacketEye CMNI CLI... Até logo!")
        return True

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    user = authenticate()
    cli = PacketEyeCMNICLI(user)
    cli.cmdloop()

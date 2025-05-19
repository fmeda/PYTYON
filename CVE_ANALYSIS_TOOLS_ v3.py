import os
import platform
import subprocess
import requests
import json
import datetime
import logging
import schedule
import time
import sys

# ---------------------------
# Verifica e instala módulos
# ---------------------------
required_packages = ["termcolor", "colorama", "requests", "schedule"]

for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

from termcolor import colored
from colorama import init as colorama_init, Fore

colorama_init()

# ---------------------------
# Configuração de log
# ---------------------------
logging.basicConfig(
    filename="cve_analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_and_print(message, level="info", color=Fore.WHITE):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    print(color + message + Fore.RESET)

# ---------------------------
# Obter atualizações instaladas
# ---------------------------
def get_installed_updates():
    system = platform.system()
    updates = set()

    try:
        if system == "Windows":
            output = subprocess.run(["wmic", "qfe", "list", "full", "/format:csv"],
                                    capture_output=True, text=True)
            updates = {line.split(',')[1] for line in output.stdout.splitlines() if "KB" in line}
        elif system == "Linux":
            output = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                                    capture_output=True, text=True)
            updates = set(output.stdout.splitlines())
        log_and_print("Atualizações do sistema obtidas com sucesso.", "info", Fore.CYAN)
    except Exception as e:
        log_and_print(f"Erro ao obter atualizações: {e}", "error", Fore.RED)

    return updates

# ---------------------------
# Buscar dados de CVEs
# ---------------------------
def fetch_cve_data():
    sources = [
        "https://cve.circl.lu/api/last",
        "https://cve.circl.lu/api/browse/microsoft",
        "https://cve.circl.lu/api/browse/linux"
    ]

    cve_data = set()
    for source in sources:
        try:
            response = requests.get(source, timeout=15)
            if response.status_code == 200:
                json_data = response.json()
                if isinstance(json_data, list):
                    cve_data.update(json_data)
                else:
                    cve_data.update(json_data.get("children", []))
                log_and_print(f"CVEs obtidos de: {source}", "info", Fore.BLUE)
            else:
                log_and_print(f"Falha ao acessar: {source}", "warning", Fore.YELLOW)
        except Exception as e:
            log_and_print(f"Erro ao buscar CVEs de {source}: {e}", "error", Fore.RED)

    return cve_data

# ---------------------------
# Analisar se atualizações possuem CVEs
# ---------------------------
def analyze_security(updates, cve_data):
    vulnerabilities = {
        cve for cve in cve_data
        if any(update in json.dumps(cve) for update in updates)
    }
    log_and_print(f"{len(vulnerabilities)} vulnerabilidades encontradas.", "info", Fore.MAGENTA)
    return vulnerabilities

# ---------------------------
# Gerar relatório
# ---------------------------
def generate_report(vulnerabilities):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"cve_report_{timestamp}.txt"
    full_path = os.path.abspath(filename)

    with open(full_path, "w", encoding="utf-8") as file:
        file.write("Relatório de Vulnerabilidades\n")
        file.write("=================================\n\n")
        for v in vulnerabilities:
            file.write(json.dumps(v, indent=2) + "\n\n")

    log_and_print(f"Relatório gerado: {full_path}", "info", Fore.GREEN)
    return full_path

# ---------------------------
# Execução principal
# ---------------------------
def main():
    log_and_print("Iniciando análise de segurança...", "info", Fore.BLUE)
    updates = get_installed_updates()
    if not updates:
        log_and_print("Nenhuma atualização detectada no sistema.", "warning", Fore.LIGHTYELLOW_EX)

    cve_data = fetch_cve_data()
    vulnerabilities = analyze_security(updates, cve_data)

    if vulnerabilities:
        log_and_print("Vulnerabilidades encontradas!", "warning", Fore.RED)
        report_path = generate_report(vulnerabilities)
        log_and_print(f"📄 Caminho do relatório: {report_path}", "info", Fore.CYAN)
    else:
        log_and_print("Nenhuma vulnerabilidade crítica encontrada.", "info", Fore.GREEN)

    log_and_print("Análise finalizada.", "info", Fore.BLUE)

# ---------------------------
# Agendamento periódico (opcional)
# ---------------------------
def schedule_analysis():
    schedule.every(5).days.do(main)
    schedule.every(10).days.do(main)
    schedule.every(15).days.do(main)

    while True:
        schedule.run_pending()
        time.sleep(3600)

# ---------------------------
# Execução
# ---------------------------
if __name__ == "__main__":
    main()
    # Para ativar agendamento, descomente:
    # schedule_analysis()

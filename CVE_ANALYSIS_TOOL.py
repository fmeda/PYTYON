import os
import platform
import requests
import json
import datetime
import subprocess
import logging
import schedule
import time
from termcolor import colored

logging.basicConfig(
    filename="cve_analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_installed_updates():
    system = platform.system()
    updates = set()
    
    if system == "Windows":
        try:
            output = subprocess.run(["wmic", "qfe", "list", "full", "/format:csv"], capture_output=True, text=True)
            updates = {line.split(',')[1] for line in output.stdout.splitlines() if "KB" in line}
            logging.info("Atualizações do Windows obtidas com sucesso.")
        except Exception as e:
            logging.error(f"Erro ao obter atualizações do Windows: {e}")
    
    elif system == "Linux":
        try:
            output = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], capture_output=True, text=True)
            updates = set(output.stdout.splitlines())
            logging.info("Atualizações do Linux obtidas com sucesso.")
        except Exception as e:
            logging.error(f"Erro ao obter atualizações do Linux: {e}")
    
    return updates

def fetch_cve_data():
    sources = [
        "https://cve.mitre.org/data/downloads/allitems.json",
        "https://nvd.nist.gov/vuln/data-feeds",
        "https://www.securityfocus.com/vulnerabilities",
        "https://www.exploit-db.com/",
        "https://www.circl.lu/services/cve-search/"
    ]
    
    cve_data = set()
    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    cve_data.update(json_data if isinstance(json_data, list) else [json_data])
                    logging.info(f"Dados de CVEs obtidos com sucesso de {source}.")
                except json.JSONDecodeError:
                    logging.warning(f"Erro ao decodificar JSON de {source}")
        except Exception as e:
            logging.error(f"Erro ao buscar CVEs de {source}: {e}")
    
    return cve_data

def analyze_security(updates, cve_data):
    vulnerabilities = {cve for cve in cve_data if any(update in str(cve) for update in updates)}
    logging.info(f"Análise de segurança concluída. {len(vulnerabilities)} vulnerabilidades encontradas.")
    return vulnerabilities

def generate_report(vulnerabilities):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"cve_report_{timestamp}.txt"
    
    with open(filename, "w") as file:
        file.write("Relatório de Vulnerabilidades\n")
        file.write("=================================\n")
        for v in vulnerabilities:
            file.write(f"{v}\n")
    
    logging.info(f"Relatório gerado: {filename}")
    print(colored(f"Relatório gerado: {filename}", "green"))

def main():
    logging.info("Iniciando análise de segurança...")
    print(colored("Iniciando análise de segurança...", "blue"))
    updates = get_installed_updates()
    cve_data = fetch_cve_data()
    vulnerabilities = analyze_security(updates, cve_data)
    
    if vulnerabilities:
        logging.warning("Vulnerabilidades encontradas!")
        print(colored("Foram encontradas vulnerabilidades!", "red"))
        generate_report(vulnerabilities)
    else:
        logging.info("Nenhuma vulnerabilidade crítica encontrada.")
        print(colored("Nenhuma vulnerabilidade crítica encontrada.", "green"))
    
    logging.info("Análise concluída!")
    print(colored("Análise concluída!", "blue"))

def schedule_analysis():
    schedule.every(5).days.do(main)
    schedule.every(10).days.do(main)
    schedule.every(15).days.do(main)
    
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Verifica a cada hora

if __name__ == "__main__":
    main()
    schedule_analysis()

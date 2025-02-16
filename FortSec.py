import paramiko
import requests
import json
import os
import time
import subprocess
from typing import List

# Configurações globais
USER = 'admin'
PRIVATE_KEY_PATH = '/path/to/ssh/private/key'
SURICATA_API = "http://localhost:4000/suricata/alerts"
CROWDSTRIKE_API = "https://api.crowdstrike.com/detect"
FIREWALL_API = "https://api.pfsense.local/block"
GEOLOCATION_API = "http://ip-api.com/json/"

# Função para verificar e instalar ferramentas necessárias
def check_and_install(tool: str, install_cmd: str):
    if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"[+] Instalando {tool}...")
        os.system(install_cmd)

# Função para execução remota via SSH
def execute_ssh_command(host: str, command: str) -> str:
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host, username=USER, key_filename=PRIVATE_KEY_PATH)
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh_client.close()
        return output if not error else f"Error: {error}"
    except Exception as e:
        return f"Failed to execute command: {e}"

# Função para análise de tráfego com Zeek
def check_zeek_logs(log_path: str):
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            logs = log_file.readlines()
            return logs
    return "Zeek logs not found."

# Função para verificar alertas do Suricata
def check_suricata_alerts():
    response = requests.get(SURICATA_API)
    if response.status_code == 200:
        return response.json()
    return {"error": "Could not fetch Suricata alerts"}

# Função para identificar ameaças via CrowdStrike Falcon
def check_crowdstrike_threats(api_key: str):
    headers = {'Authorization': f'Bearer {api_key}'}
    response = requests.get(CROWDSTRIKE_API, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {"error": "Unable to fetch threat data"}

# Função para obter localização do IP do atacante
def get_geolocation(ip: str):
    response = requests.get(f"{GEOLOCATION_API}{ip}")
    if response.status_code == 200:
        return response.json()
    return {"error": "Could not determine geolocation"}

# Função para mitigar ameaças bloqueando IPs suspeitos
def mitigate_threat(ip: str, api_key: str):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    data = {"ip": ip, "action": "block"}
    response = requests.post(FIREWALL_API, json=data, headers=headers)
    return response.json()

# Função para gerar relatório do ataque
def generate_attack_report(attacker_ip: str, geo_info: dict, threats: dict, mitigations: dict):
    report = f"""
    --- Relatório de Segurança ---
    IP do atacante: {attacker_ip}
    Localização: {geo_info.get('city')}, {geo_info.get('country')}
    Alertas Identificados: {json.dumps(threats, indent=4)}
    Medidas Tomadas: {json.dumps(mitigations, indent=4)}
    """
    with open("attack_report.txt", "w") as f:
        f.write(report)
    print("[+] Relatório gerado com sucesso! Verifique attack_report.txt")

# Execução principal
def main():
    print("[+] Verificando e instalando ferramentas necessárias...")
    check_and_install("zeek", "sudo apt install zeek -y")
    check_and_install("suricata", "sudo apt install suricata -y")
    
    print("[+] Analisando tráfego de rede via Zeek...")
    zeek_logs = check_zeek_logs("/var/log/zeek/conn.log")
    print(zeek_logs)
    
    print("[+] Verificando alertas do Suricata...")
    suricata_alerts = check_suricata_alerts()
    print(suricata_alerts)
    
    print("[+] Identificando ameaças via CrowdStrike...")
    threats = check_crowdstrike_threats("your_api_key")
    print(threats)
    
    attacker_ip = threats.get('suspicious_ips', [None])[0]
    geo_info = get_geolocation(attacker_ip) if attacker_ip else {}
    mitigations = {}
    
    if attacker_ip:
        print(f"[!] Bloqueando IP suspeito: {attacker_ip}")
        mitigations = mitigate_threat(attacker_ip, "your_api_key")
        print(mitigations)
    
    generate_attack_report(attacker_ip, geo_info, threats, mitigations)
    print("[+] Operação concluída!")

if __name__ == "__main__":
    main()

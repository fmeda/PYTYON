import os
import subprocess
import json
import joblib
import numpy as np
import paramiko
import platform
from flask import Flask, render_template, jsonify
from sklearn.ensemble import IsolationForest
import requests

# Nome do programa
PROGRAM_NAME = "SecureGuardian - Sistema de Hardening e Monitoramento Inteligente"

def log_action(action, result, log_file="/var/log/secureguardian.log"):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as log:
        log.write(f"{action}: {result}\n")

def install_dependencies():
    system = platform.system().lower()
    package_managers = {
        "linux": "sudo apt-get install -y",
        "darwin": "brew install",
    }
    packages = ["ufw", "suricata", "grafana", "zabbix-agent", "prometheus", "wazuh-agent", "openssh"]
    
    if system in package_managers:
        for package in packages:
            subprocess.run(f"{package_managers[system]} {package}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_action("Install", f"Checked and installed {package}")
    elif "android" in system or "ios" in system:
        print("A instalação automática não é suportada neste sistema. Utilize Termux (Android) ou um ambiente Unix compatível.")

def remote_ssh_execution(server_ip, user, password, command):
    try:
        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(server_ip, username=user, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            output, error = stdout.read().decode(), stderr.read().decode()
            return output if output else error
    except Exception as e:
        return str(e)

def display_menu():
    menu_options = {
        "1": ("Verificar Segurança do Sistema", check_linux_security),
        "2": ("Aplicar Hardening", apply_linux_hardening),
        "3": ("Analisar Tráfego de Rede", analyze_network_traffic),
        "4": ("Gerar Relatórios no Grafana", generate_grafana_reports),
        "5": ("Monitoramento Inteligente (IA)", detect_anomalies),
        "6": ("Acesso Remoto via SSH", remote_ssh_menu),
        "7": ("Sair", exit)
    }
    
    while True:
        print(f"\n{PROGRAM_NAME}\n")
        for key, (desc, _) in menu_options.items():
            print(f"{key}. {desc}")
        
        choice = input("Escolha uma opção: ")
        if choice in menu_options:
            func = menu_options[choice][1]
            func() if callable(func) else print("Opção inválida.")
        else:
            print("Opção inválida, tente novamente.")

def remote_ssh_menu():
    ip = input("Digite o IP do servidor remoto: ")
    user = input("Digite o usuário: ")
    password = input("Digite a senha: ")
    command = input("Digite o comando a ser executado: ")
    print(remote_ssh_execution(ip, user, password, command))

if __name__ == "__main__":
    install_dependencies()
    display_menu()

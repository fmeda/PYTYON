#!/usr/bin/env python3
"""
FIPSL Pro v1.0 - Ferramenta Investigativa Profissional para Servidores Linux
Por: Kali GPT 🐉
"""

import os
import subprocess
import hashlib
import shutil
import json
import platform
import sys
from datetime import datetime

REQUIRED_TOOLS = [
    "nmap", "aide", "rkhunter", "chkrootkit", "auditd",
    "net-tools", "ss", "iftop", "debsums", "whois",
    "nikto", "wireshark", "python3-pip"
]

LOG_PATH = "/var/log/fipslpro"
REPORT_PATH = "/var/log/fipslpro/reports"
INTEGRITY_FILE = "/usr/local/bin/fipsl_integrity.sha512"

def install_dependencies():
    print("\n[+] Verificando dependências essenciais...")
    
    if platform.system() != "Linux":
        print("[-] Este script só é compatível com sistemas Linux baseados em Debian.")
        print("[-] Encerrando execução.")
        sys.exit(1)

    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            print(f"    - {tool} [ausente]")
            missing.append(tool)
        else:
            print(f"    - {tool} [ok]")

    if missing:
        print("\n[+] Instalando dependências ausentes...")
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y"] + missing, check=True)
            print("[+] Instalação concluída.\n")
        except subprocess.CalledProcessError as e:
            print(f"[-] Erro durante instalação: {e}")
    else:
        print("[+] Todas as dependências estão satisfeitas.\n")

def generate_integrity_hash(file_path):
    sha512 = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha512.update(chunk)
    return sha512.hexdigest()

def verify_integrity():
    if not os.path.exists(INTEGRITY_FILE):
        print("[-] Arquivo de integridade não encontrado.")
        return False
    with open(INTEGRITY_FILE, "r") as f:
        saved_hash = f.read().strip()
    current_hash = generate_integrity_hash(__file__)
    if saved_hash == current_hash:
        print("[+] Integridade do código verificada com sucesso.")
        return True
    else:
        print("[-] Integridade do código VIOLADA!")
        return False

def save_integrity():
    hash_value = generate_integrity_hash(__file__)
    with open(INTEGRITY_FILE, "w") as f:
        f.write(hash_value)
    print(f"[+] Hash salvo em {INTEGRITY_FILE}")

def create_report_dir():
    os.makedirs(REPORT_PATH, exist_ok=True)

def main_menu():
    while True:
        print("""
============================
 FIPSL Pro v1.0 - Menu CLI
============================
[1] Auditoria Local Completa
[2] Auditoria Remota via SSH
[3] Gerar Relatório Executivo
[4] Verificar Integridade do Código
[0] Sair
============================
""")
        choice = input("Escolha uma opção: ").strip()
        if choice == "1":
            print("[*] Executando auditoria local... (em desenvolvimento)")
        elif choice == "2":
            print("[*] Auditoria remota ainda não implementada.")
        elif choice == "3":
            print("[*] Gerando relatório executivo... (em desenvolvimento)")
        elif choice == "4":
            verify_integrity()
        elif choice == "0":
            break
        else:
            print("[-] Opção inválida. Tente novamente.")

if __name__ == "__main__":
    install_dependencies()
    create_report_dir()
    main_menu()

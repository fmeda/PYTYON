#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fortinet Analyst CLI Tool v2.0
Autor: Fabiano Aparecido
Descrição: CLI interativa profissional para analistas de rede Fortinet.
Versão: 2.0
"""

import sys
import os
import subprocess
import time
from datetime import datetime

# ======================
# Pre-check de módulos
# ======================
required_modules = ["colorama", "paramiko", "requests"]
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        print(f"Instalando dependência {module}... Aguarde, quase pronto! 🚀")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

import colorama
from colorama import Fore, Style
import paramiko
import requests

colorama.init(autoreset=True)

# ======================
# Logs de auditoria
# ======================
LOG_FILE = "fortinet_cli_audit.log"

def log_action(action, status="INFO"):
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] [{status}] {action}\n")

# ======================
# Funções auxiliares
# ======================
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    clear_screen()
    print(Fore.CYAN + "="*70)
    print(Fore.CYAN + f"{title.center(70)}")
    print(Fore.CYAN + "="*70 + "\n")

def wait_for_enter():
    try:
        input(Fore.YELLOW + "\nTudo certo até aqui! Pressione ENTER para voltar ao menu...")
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⚠️ Entrada cancelada pelo usuário. Retornando ao menu...")
        time.sleep(1)

def ssh_execute(host, user, password, command):
    """Executa comandos via SSH em FortiGate"""
    try:
        print(Fore.BLUE + "Conectando ao FortiGate, aguarde um momento...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=user, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        client.close()
        if error:
            print(Fore.RED + f"Oops! Algo deu errado: {error}")
            log_action(f"Erro SSH comando: {command} em {host}", "ERROR")
        else:
            print(Fore.GREEN + f"🎉 Comando executado com sucesso!\n{output}")
            log_action(f"SSH comando executado: {command} em {host}", "SUCCESS")
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⚠️ Operação SSH cancelada pelo usuário. Retornando ao menu...")
        log_action(f"SSH cancelado pelo usuário em {host}", "WARNING")
    except Exception as e:
        print(Fore.RED + f"Falha ao conectar via SSH: {e}. Verifique os dados e tente novamente.")
        log_action(f"Falha SSH {host}: {e}", "ERROR")

# ======================
# Funções do menu operacional
# ======================
def monitoramento_operacao():
    print_header("Monitoramento e Operação de Rede")
    print("1. Verificar status do FortiGate")
    print("2. Coletar logs críticos")
    print("0. Voltar")
    try:
        choice = input("\nEscolha uma opção: ")
        if choice == "1":
            host = input("IP do FortiGate: ")
            user = input("Usuário SSH: ")
            password = input("Senha SSH: ")
            print(Fore.YELLOW + "🔎 Conectando e verificando status...")
            ssh_execute(host, user, password, "get system status")
            wait_for_enter()
        elif choice == "2":
            host = input("IP do FortiGate: ")
            user = input("Usuário SSH: ")
            password = input("Senha SSH: ")
            print(Fore.YELLOW + "📄 Coletando logs críticos...")
            ssh_execute(host, user, password, "execute log display")
            wait_for_enter()
        else:
            print(Fore.RED + "Opção inválida, mas não desista! 😄")
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⚠️ Operação cancelada pelo usuário. Retornando ao menu...")
        time.sleep(1)

def backup_documentacao():
    print_header("Backup de Configurações FortiGate")
    try:
        host = input("IP do FortiGate: ")
        user = input("Usuário SSH: ")
        password = input("Senha SSH: ")
        print(Fore.YELLOW + "💾 Iniciando backup da configuração...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"backup_{host}_{timestamp}.conf"
        ssh_execute(host, user, password, f"execute backup config flash {backup_file}")
        print(Fore.GREEN + f"✅ Backup concluído com sucesso! Arquivo: {backup_file}")
        log_action(f"Backup realizado: {backup_file}", "SUCCESS")
        wait_for_enter()
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⚠️ Backup cancelado pelo usuário. Retornando ao menu...")
        time.sleep(1)

# ======================
# Menu principal
# ======================
def main_menu():
    while True:
        try:
            print_header("Fortinet Analyst CLI Tool v2.0")
            print("1️⃣ Monitoramento e Operação de Rede")
            print("2️⃣ Backup e Documentação")
            print("0️⃣ Sair")
            choice = input("\nEscolha uma opção: ")
            if choice == '1':
                monitoramento_operacao()
            elif choice == '2':
                backup_documentacao()
            elif choice == '0':
                print(Fore.CYAN + "\n👋 Saindo da ferramenta... Até breve e bons diagnósticos!")
                sys.exit(0)
            else:
                print(Fore.RED + "\nOpção inválida! Tente novamente com calma. 😉")
                time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.MAGENTA + "\n⚠️ Operação cancelada pelo usuário (Ctrl+C). Retornando ao menu...")
            time.sleep(1)
            continue

# ======================
# Opção --help
# ======================
def show_help():
    print("""
Fortinet Analyst CLI Tool v2.0 - Ajuda

Descrição:
Interface CLI interativa profissional para analistas de rede Fortinet.
Permite:
- Monitorar status e logs críticos do FortiGate
- Realizar backup de configuração via SSH
- Registrar logs detalhados de auditoria

Uso:
    python fortinet_cli_v2.py         -> Executa a ferramenta interativa
    python fortinet_cli_v2.py --help  -> Mostra esta mensagem de ajuda

💡 Dica: Sempre confira suas credenciais SSH antes de executar comandos.
""")

# ======================
# Entry point
# ======================
if __name__ == "__main__":
    try:
        if '--help' in sys.argv:
            show_help()
        else:
            print(Fore.CYAN + "Bem-vindo ao Fortinet Analyst CLI Tool! 🚀")
            print(Fore.CYAN + "Preparando o ambiente, aguarde um instante...\n")
            time.sleep(1)
            main_menu()
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⚠️ Programa encerrado pelo usuário. Até logo! 👋")

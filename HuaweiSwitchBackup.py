#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Huawei Switch Backup Automation Script
--------------------------------------
Backup automatizado e interativo de switches Huawei via SSH.
"""

import sys
import os
import getpass
import signal
import time
import csv
import threading
from datetime import datetime

# Pré-check de módulos
required_modules = ["paramiko", "argparse", "colorama"]
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(f"[ERRO] Módulos ausentes: {', '.join(missing_modules)}")
    print("Instale com: pip install " + " ".join(missing_modules))
    sys.exit(1)

import paramiko
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# Tratamento Ctrl+C
def signal_handler(sig, frame):
    print(Fore.YELLOW + "\n[INFO] Execução interrompida pelo usuário.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Loader animado
def loading(msg, duration=2):
    print(msg, end="", flush=True)
    for _ in range(duration):
        for c in "|/-\\":
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\b")
    print("")

# Função de backup
def backup_switch(host, username, password, output_dir="backups", results=None):
    try:
        loading(Fore.CYAN + f"[INFO] Conectando ao switch {host} ...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10)
        
        stdin, stdout, stderr = ssh.exec_command("display current-configuration")
        config = stdout.read().decode()

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"{host}_{timestamp}.cfg")
        with open(filename, "w") as f:
            f.write(config)

        print(Fore.GREEN + f"[SUCESSO] Backup salvo em: {filename}")
        ssh.close()
        if results is not None:
            results[host] = "SUCESSO"
    except paramiko.AuthenticationException:
        print(Fore.RED + f"[ERRO] Falha de autenticação no switch {host}")
        if results is not None:
            results[host] = "FALHA (auth)"
    except paramiko.SSHException as e:
        print(Fore.RED + f"[ERRO] Problema SSH no switch {host}: {e}")
        if results is not None:
            results[host] = "FALHA (ssh)"
    except Exception as e:
        print(Fore.RED + f"[ERRO] Erro inesperado: {e}")
        if results is not None:
            results[host] = "FALHA (erro)"

# Backup múltiplo
def backup_multiple(csv_file, username, password, output_dir="backups"):
    results = {}
    threads = []
    with open(csv_file, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            host = row[0].strip()
            t = threading.Thread(target=backup_switch, args=(host, username, password, output_dir, results))
            threads.append(t)
            t.start()
    for t in threads:
        t.join()
    print(Fore.CYAN + "\n[RESUMO] Resultado dos backups:")
    for host, status in results.items():
        color = Fore.GREEN if "SUCESSO" in status else Fore.RED
        print(f"  {host}: {color}{status}")

# Menu interativo
def interactive_menu():
    while True:
        print(Style.BRIGHT + Fore.CYAN + "\n=== Huawei Switch Backup Automation ===")
        print("1. Backup único")
        print("2. Backup múltiplo (CSV)")
        print("3. Configurações avançadas")
        print("4. Sair")

        choice = input(Fore.YELLOW + "Escolha uma opção: ").strip()

        if choice == "1":
            host = input("IP/Hostname do switch: ").strip()
            user = input("Usuário SSH: ").strip()
            password = getpass.getpass("Senha SSH: ")
            backup_switch(host, user, password)
        elif choice == "2":
            csv_file = input("Informe o caminho do arquivo CSV com IPs: ").strip()
            if not os.path.exists(csv_file):
                print(Fore.RED + "[ERRO] Arquivo CSV não encontrado.")
                continue
            user = input("Usuário SSH: ").strip()
            password = getpass.getpass("Senha SSH: ")
            backup_multiple(csv_file, user, password)
        elif choice == "3":
            print(Fore.CYAN + "[INFO] Configurações avançadas ainda em desenvolvimento...")
        elif choice == "4":
            print(Fore.GREEN + "[INFO] Saindo do programa. Até logo!")
            break
        else:
            print(Fore.RED + "[ERRO] Opção inválida. Tente novamente.")

# CLI por argumentos
def cli_mode():
    parser = argparse.ArgumentParser(
        description="Backup automatizado de switches Huawei",
        epilog="Exemplo: python huawei_backup.py --host 10.0.0.1 --user admin"
    )
    parser.add_argument("--host", help="IP ou hostname do switch", required=False)
    parser.add_argument("--user", help="Usuário SSH", required=False)
    parser.add_argument("--csv", help="Arquivo CSV com lista de switches", required=False)
    parser.add_argument("--output", help="Diretório de backup", default="backups")
    args = parser.parse_args()

    if args.csv:
        password = getpass.getpass(f"Senha para {args.user}: ")
        backup_multiple(args.csv, args.user, password, args.output)
    elif args.host and args.user:
        password = getpass.getpass(f"Senha para {args.user}@{args.host}: ")
        backup_switch(args.host, args.user, password, args.output)
    else:
        interactive_menu()

if __name__ == "__main__":
    cli_mode()

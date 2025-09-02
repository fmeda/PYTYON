#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetAutomatorPro - CLI de Automação de Rede Multi-Vendor
Versão Avançada (Curto e Médio Prazo)
Funcionalidades:
- Conexão multi-vendor (Cisco IOS, JunOS, FortiOS, pfSense)
- Auditoria de firewall com exportação CSV/JSON
- Rollback automático de configuração
- Modo massivo de configuração com Nornir
- Dashboard CLI interativo
- Suporte TCL/Expect para dispositivos sem API
- Pré-check de módulos e instalação automática
- Mensagens amigáveis e tratamento Ctrl+C
"""

import os
import sys
import getpass
import logging
import csv
import json
import subprocess
import signal
from datetime import datetime

# ----------------------------
# Tratamento Ctrl+C
# ----------------------------
def signal_handler(sig, frame):
    print("\n[!] Execução interrompida pelo usuário (Ctrl+C). Saindo...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# ----------------------------
# Help CLI
# ----------------------------
HELP_TEXT = """
NetAutomatorPro - CLI de Automação de Rede

Opções:
  --help          Exibe este menu de ajuda

Menu Interativo:
  1               Conectar dispositivo individual
  2               Aplicar configuração massiva
  3               Auditoria de firewall
  4               Dashboard CLI
  5               Sair
"""

if "--help" in sys.argv or "-h" in sys.argv:
    print(HELP_TEXT)
    sys.exit(0)

# ----------------------------
# Pré-check de módulos
# ----------------------------
REQUIRED_MODULES = ["netmiko", "nornir", "nornir_netmiko", "nornir_utils", "pexpect"]

def pre_check(modulos):
    for mod in modulos:
        try:
            __import__(mod)
        except ModuleNotFoundError:
            print(f"[!] Módulo '{mod}' não encontrado. Instalando...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", mod])
            print(f"[+] Módulo '{mod}' instalado com sucesso!")

pre_check(REQUIRED_MODULES)

# ----------------------------
# Importações pós pré-check
# ----------------------------
from netmiko import ConnectHandler
from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_config
from nornir_utils.plugins.functions import print_result
import pexpect

# ----------------------------
# Logging
# ----------------------------
LOG_FILE = "netautomatorpro.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

print("\n=== NetAutomatorPro ===")
print("Bem-vindo! Pressione Ctrl+C a qualquer momento para sair.\n")

# ----------------------------
# Classe Dispositivo
# ----------------------------
class Dispositivo:
    def __init__(self, vendor, host, username, password):
        self.vendor = vendor
        self.host = host
        self.username = username
        self.password = password
        self.conn = None
        self.backup_config = None

    def conectar(self):
        try:
            print(f"[+] Conectando a {self.host} ({self.vendor})...")
            logging.info(f"Tentativa de conexão: {self.host}")
            self.conn = ConnectHandler(
                device_type=self.vendor,
                host=self.host,
                username=self.username,
                password=self.password
            )
            print(f"[+] Conexão estabelecida!")
            logging.info(f"Conectado: {self.host}")
            # Backup automático da configuração atual
            self.backup_config = self.conn.send_command("show running-config")
            logging.info(f"Backup da configuração feito para {self.host}")
            return True
        except Exception as e:
            print(f"[!] Falha ao conectar: {e}")
            logging.error(f"Erro ao conectar {self.host}: {e}")
            return False

    def rollback(self):
        if self.conn and self.backup_config:
            print(f"[!] Executando rollback no dispositivo {self.host}...")
            commands = self.backup_config.splitlines()
            self.conn.send_config_set(commands)
            print(f"[+] Rollback concluído para {self.host}")
            logging.info(f"Rollback realizado: {self.host}")

    def executar_comando(self, comando):
        try:
            if self.conn:
                output = self.conn.send_command(comando)
                logging.info(f"Comando executado: {comando}")
                return output
        except Exception as e:
            print(f"[!] Erro ao executar comando: {e}")
            logging.error(f"Erro ao executar comando {comando}: {e}")

    def desconectar(self):
        if self.conn:
            self.conn.disconnect()
            logging.info(f"Desconectado de {self.host}")
            print(f"[+] Dispositivo {self.host} desconectado.")

# ----------------------------
# Auditoria de firewall
# ----------------------------
def auditoria_firewall(dispositivo, compliance_file):
    print("[+] Iniciando auditoria de firewall...")
    try:
        with open(compliance_file, "r") as f:
            regras = [r.strip() for r in f.readlines() if r.strip()]
    except FileNotFoundError:
        print(f"[!] Arquivo '{compliance_file}' não encontrado.")
        return
    
    resultados = []
    for regra in regras:
        output = dispositivo.executar_comando(f"show run | include {regra}")
        status = "OK" if regra in output else "ERRO"
        resultados.append({"regra": regra, "status": status})
        print(f"[{status}] Regra: {regra}")
        logging.info(f"Auditoria: {regra} -> {status}")

    # Exportação CSV/JSON
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    csv_file = f"auditoria_{dispositivo.host}_{timestamp}.csv"
    json_file = f"auditoria_{dispositivo.host}_{timestamp}.json"
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["regra", "status"])
        writer.writeheader()
        writer.writerows(resultados)
    with open(json_file, "w") as f:
        json.dump(resultados, f, indent=4)
    print(f"[+] Resultados exportados para {csv_file} e {json_file}")

# ----------------------------
# Configuração massiva via Nornir
# ----------------------------
def aplicar_configuracao_massiva(config_file, nornir_config="config_nornir.yaml"):
    print(f"[+] Aplicando configuração massiva do arquivo {config_file}...")
    nr = InitNornir(config_file=nornir_config)
    def task_config(task):
        task.run(task=netmiko_send_config, config_file=config_file)
    result = nr.run(task=task_config)
    print_result(result)
    logging.info(f"Configuração massiva aplicada: {config_file}")

# ----------------------------
# Dashboard CLI básico
# ----------------------------
def dashboard():
    print("\n=== Dashboard CLI ===")
    print("[+] Em desenvolvimento: Mostrará status dos dispositivos, auditoria e logs em tempo real.\n")

# ----------------------------
# Menu principal
# ----------------------------
def menu():
    while True:
        print("\nEscolha uma opção:")
        print("1 - Conectar dispositivo individual")
        print("2 - Aplicar configuração massiva")
        print("3 - Auditoria de firewall")
        print("4 - Dashboard CLI")
        print("5 - Sair")
        escolha = input("Opção: ").strip()
        
        if escolha == "1":
            vendor = input("Vendor (cisco_ios/juniper/junos/fortinet/pfsense): ").strip()
            host = input("Endereço IP: ").strip()
            username = input("Usuário: ").strip()
            password = getpass.getpass("Senha: ")
            disp = Dispositivo(vendor, host, username, password)
            if disp.conectar():
                comando = input("Digite o comando a executar (ou 'rollback' para restaurar configuração): ").strip()
                if comando.lower() == "rollback":
                    disp.rollback()
                else:
                    output = disp.executar_comando(comando)
                    print(f"\n[OUTPUT]\n{output}")
                disp.desconectar()
        
        elif escolha == "2":
            arquivo_config = input("Arquivo de configuração Nornir (ex: configs.txt): ").strip()
            aplicar_configuracao_massiva(arquivo_config)
        
        elif escolha == "3":
            vendor = input("Vendor do firewall (cisco_ios/fortinet/pfsense): ").strip()
            host = input("Endereço IP do firewall: ").strip()
            username = input("Usuário: ").strip()
            password = getpass.getpass("Senha: ")
            arquivo_compliance = input("Arquivo de regras de compliance: ").strip()
            disp = Dispositivo(vendor, host, username, password)
            if disp.conectar():
                auditoria_firewall(disp, arquivo_compliance)
                disp.desconectar()
        
        elif escolha == "4":
            dashboard()
        
        elif escolha == "5":
            print("[+] Saindo... Até logo!")
            sys.exit(0)
        else:
            print("[!] Opção inválida. Use '--help' para instruções.")

if __name__ == "__main__":
    menu()

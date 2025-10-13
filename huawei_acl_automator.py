#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huawei ACL Automator v2.0
Autor: Fabiano Aparecido
Descrição:
  Ferramenta interativa e inteligente para criação, validação e exportação de regras ACL
  em equipamentos Huawei (Switches, Roteadores, Firewalls USG/NE/CE).
Compatibilidade: Windows / Linux / macOS
"""

import os
import sys
import json
import time
import ipaddress
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.progress import track
from datetime import datetime

# === Inicialização === #
console = Console()
VERSION = "2.0"
LOG_FILE = "huawei_acl_automator.log"
CONFIG_FILE = "acl_config.json"

# === Funções Utilitárias === #

def log(msg: str):
    """Registra logs com timestamp."""
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def validar_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def validar_porta(porta):
    return porta.isdigit() and 0 < int(porta) < 65536

def exportar_acl(nome_arquivo, conteudo):
    with open(nome_arquivo, "w") as f:
        f.write(conteudo)
    console.print(f"✅ Arquivo [green]{nome_arquivo}[/green] exportado com sucesso!")
    log(f"Exportado ACL para {nome_arquivo}")

# === Núcleo Principal === #

def criar_acl():
    console.print("\n[bold cyan]=== Huawei ACL Automator ===[/bold cyan]")
    acl_name = Prompt.ask("Nome da ACL (ex: ACL_Internet_Acesso)")
    acl_type = Prompt.ask("Tipo de ACL", choices=["basic", "advanced", "layer2"], default="advanced")
    acl_number = Prompt.ask("Número da ACL (ex: 3000)")
    rule_action = Prompt.ask("Ação da Regra", choices=["permit", "deny"], default="permit")
    protocol = Prompt.ask("Protocolo", choices=["ip", "tcp", "udp", "icmp", "any"], default="ip")
    
    src_ip = Prompt.ask("Endereço de Origem (ex: 192.168.1.0/24)")
    while not validar_ip(src_ip):
        src_ip = Prompt.ask("[red]IP inválido[/red]. Digite novamente:")

    dst_ip = Prompt.ask("Endereço de Destino (ex: 10.0.0.0/24)")
    while not validar_ip(dst_ip):
        dst_ip = Prompt.ask("[red]IP inválido[/red]. Digite novamente:")

    src_port = Prompt.ask("Porta de Origem (opcional)", default="any")
    if src_port != "any" and not validar_porta(src_port):
        console.print("[yellow]Porta inválida, será usado 'any'[/yellow]")
        src_port = "any"

    dst_port = Prompt.ask("Porta de Destino (opcional)", default="any")
    if dst_port != "any" and not validar_porta(dst_port):
        console.print("[yellow]Porta inválida, será usado 'any'[/yellow]")
        dst_port = "any"

    description = Prompt.ask("Descrição da Regra (opcional)", default="Regra Automática Huawei ACL")

    # === Geração === #
    acl_template = f"""
system-view
acl {acl_type} {acl_number} name {acl_name}
 rule 5 {rule_action} {protocol} source {src_ip} destination {dst_ip} \
source-port {src_port} destination-port {dst_port}
 description {description}
quit
save
"""
    console.print("\n[bold green]Regra gerada com sucesso:[/bold green]")
    console.print(acl_template)

    # Confirmação e Exportação
    if Confirm.ask("Deseja exportar esta ACL para um arquivo?"):
        nome_arquivo = f"ACL_{acl_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        exportar_acl(nome_arquivo, acl_template)

    # Simulação de Aplicação
    if Confirm.ask("Deseja simular a aplicação desta ACL (sem enviar comandos reais)?"):
        for step in track(range(5), description="Simulando aplicação no equipamento..."):
            time.sleep(0.5)
        console.print("✅ Simulação concluída com sucesso!")

    log(f"ACL criada: {acl_name}, Tipo: {acl_type}, Ação: {rule_action}, Src: {src_ip}, Dst: {dst_ip}")

# === Menu Principal === #

def main_menu():
    while True:
        console.print("\n[bold cyan]Huawei ACL Automator - Menu[/bold cyan]")
        console.print("1️⃣  Criar nova ACL")
        console.print("2️⃣  Visualizar logs")
        console.print("3️⃣  Exibir versão")
        console.print("4️⃣  Sair")

        escolha = Prompt.ask("Escolha uma opção", choices=["1", "2", "3", "4"])
        if escolha == "1":
            criar_acl()
        elif escolha == "2":
            os.system(f"type {LOG_FILE}" if os.name == "nt" else f"cat {LOG_FILE}")
        elif escolha == "3":
            console.print(f"\n🔖 Versão atual: {VERSION}")
        elif escolha == "4":
            console.print("👋 Saindo do programa. Até breve!")
            sys.exit(0)

# === Execução Principal === #
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Execução interrompida pelo usuário.[/red]")
        sys.exit(1)

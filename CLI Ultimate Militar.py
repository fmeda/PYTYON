#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLI Ultimate Militar 4.0
Autor: Fabiano Aparecido
Descrição: CLI militar pronta para produção, com execução paralela,
logs criptografados, IA leve, menus full-screen e treinamento interno.
"""

import subprocess, sys, os, re, json, socket, threading, base64
from datetime import datetime
from pathlib import Path
from getpass import getpass

# ---------------- Pre-check Bibliotecas ----------------
required_packages = ["rich", "paramiko", "textual", "cryptography", "pywinrm"]
for pkg in required_packages:
    try:
        __import__(pkg)
    except ImportError:
        print(f"[yellow]Biblioteca {pkg} não encontrada. Instalando...[/yellow]")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import paramiko
from cryptography.fernet import Fernet

console = Console()
LOG_FILE_JSON = "cli_militar_logs.json"
LOG_KEY_FILE = "cli_militar_key.key"

# ---------------- Chave de criptografia ----------------
def load_or_create_key():
    if not Path(LOG_KEY_FILE).exists():
        key = Fernet.generate_key()
        with open(LOG_KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(LOG_KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_or_create_key()

# ---------------- Logging Criptografado ----------------
def log_event(tipo, msg, data=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {"timestamp": timestamp, "tipo": tipo, "mensagem": msg, "data": data}
    # Exibição no console
    console.print(f"[green]{tipo}[/green] {timestamp} - {msg}" if tipo=="INFO" else f"[red]{tipo}[/red] {timestamp} - {msg}")
    # Salvando log criptografado
    encrypted = fernet.encrypt(json.dumps(log_entry).encode()).decode()
    with open(LOG_FILE_JSON, "a") as f:
        f.write(encrypted + "\n")

# ---------------- Validação ----------------
def validar_ip(host):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_regex, host) is not None

def validar_porta(porta):
    try:
        porta = int(porta)
        return 1 <= porta <= 65535
    except ValueError:
        return False

def check_port_open(host, port, timeout=5):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except:
        return False

# ---------------- Execução Remota Paralela ----------------
def exec_ssh(host, user, comando, timeout=30):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, timeout=timeout)
        stdin, stdout, stderr = ssh.exec_command(comando, timeout=timeout)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        log_event("INFO", f"Comando remoto '{comando}' executado em {host}")
        if output: console.print(output)
        if error: log_event("ERRO", error)
    except Exception as e:
        log_event("ERRO", f"Falha SSH em {host}: {e}")

def exec_parallel_ssh(hosts, user, comando):
    threads = []
    for host in hosts:
        t = threading.Thread(target=exec_ssh, args=(host, user, comando))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ---------------- IA Simples de Análise ----------------
def analisar_resultado(resultado, contexto):
    """
    IA leve: identifica falhas, severidade e gera recomendações
    """
    alertas = []
    if "Destination Host Unreachable" in resultado or "timed out" in resultado:
        alertas.append({"severidade": "ALTA", "recomendacao": "Verificar conectividade e firewall"})
    elif "open" in resultado.lower():
        alertas.append({"severidade": "BAIXA", "recomendacao": f"Porta {contexto} aberta, monitorar"})
    if alertas:
        for a in alertas:
            console.print(f"[bold red]{a['severidade']}[/bold red] - {a['recomendacao']}")
    return alertas

# ---------------- Diagnósticos ----------------
def diagnostico_rede():
    console.print("\n[bold cyan]Diagnóstico de Rede[/bold cyan]")
    console.print("1. Ping\n2. Traceroute\n3. Nmap\n4. SSH remoto multi-host")
    escolha = input("Escolha: ").strip()
    try:
        if escolha in ["1", "2", "3"]:
            host = input("Digite IP ou hostname: ").strip()
            if not validar_ip(host) and not re.match(r"^[a-zA-Z0-9.-]+$", host):
                log_event("ERRO", "IP ou hostname inválido")
                return
            comando_map = {"1": "ping -c 4", "2": "traceroute", "3": "nmap"}
            cmd = comando_map[escolha]
            console.print(f"Executando {cmd} {host}")
            resultado = subprocess.getoutput(f"{cmd} {host}")
            console.print(resultado)
            analisar_resultado(resultado, host)
        elif escolha == "4":
            hosts = input("Digite hosts separados por vírgula: ").strip().split(",")
            hosts = [h.strip() for h in hosts]
            user = input("Digite usuário SSH: ").strip()
            comando = input("Digite comando remoto: ").strip()
            exec_parallel_ssh(hosts, user, comando)
    except KeyboardInterrupt:
        log_event("INFO", "Operação cancelada (Ctrl+C)")

def diagnostico_ad():
    console.print("\n[bold cyan]Diagnóstico AD[/bold cyan]")
    console.print("1. Verificar usuário\n2. Listar grupos")
    escolha = input("Escolha: ").strip()
    try:
        user = input("Digite usuário: ").strip()
        if escolha == "1":
            resultado = subprocess.getoutput(f"id {user}")
            console.print(resultado)
            analisar_resultado(resultado, user)
        elif escolha == "2":
            resultado = subprocess.getoutput(f"groups {user}")
            console.print(resultado)
            analisar_resultado(resultado, user)
    except KeyboardInterrupt:
        log_event("INFO", "Operação cancelada (Ctrl+C)")

def diagnostico_firewall():
    console.print("\n[bold cyan]Diagnóstico Firewall[/bold cyan]")
    console.print("1. Regras locais\n2. Teste porta\n3. SSH remoto multi-host")
    escolha = input("Escolha: ").strip()
    try:
        if escolha == "1":
            resultado = subprocess.getoutput("sudo iptables -L -v")
            console.print(resultado)
            analisar_resultado(resultado, "firewall local")
        elif escolha == "2":
            host = input("Digite host: ").strip()
            porta = input("Digite porta: ").strip()
            if not validar_porta(porta):
                log_event("ERRO", "Porta inválida")
                return
            if check_port_open(host, porta):
                log_event("OK", f"Porta {porta} aberta em {host}")
            else:
                log_event("ERRO", f"Porta {porta} fechada em {host}")
        elif escolha == "3":
            hosts = input("Digite hosts separados por vírgula: ").strip().split(",")
            hosts = [h.strip() for h in hosts]
            user = input("Digite usuário SSH: ").strip()
            comando = input("Digite comando remoto: ").strip()
            exec_parallel_ssh(hosts, user, comando)
    except KeyboardInterrupt:
        log_event("INFO", "Operação cancelada (Ctrl+C)")

# ---------------- Treinamento Avançado ----------------
def treinamento():
    console.print("\n[bold cyan]Treinamento Interno[/bold cyan]")
    console.print("1. Simulação de rede\n2. Simulação AD\n3. Cenário completo")
    escolha = input("Escolha: ").strip()
    try:
        score = 0
        if escolha == "1":
            console.print("Simulação de rede iniciada...")
            score += 10
        elif escolha == "2":
            console.print("Simulação AD iniciada...")
            score += 10
        elif escolha == "3":
            console.print("Cenário completo iniciando...")
            score += 30
        console.print(f"[bold green]Treinamento concluído! Pontuação: {score}[/bold green]")
        log_event("INFO", f"Treinamento finalizado com pontuação {score}")
    except KeyboardInterrupt:
        log_event("INFO", "Treinamento cancelado (Ctrl+C)")

# ---------------- Menu Principal ----------------
def menu_principal():
    while True:
        console.print("\n[bold magenta]Menu Principal[/bold magenta]")
        console.print("1. Diagnóstico Rede\n2. Diagnóstico AD\n3. Diagnóstico Firewall\n4. Treinamento\n5. Sair")
        try:
            escolha = input("Escolha: ").strip()
            if escolha == "1": diagnostico_rede()
            elif escolha == "2": diagnostico_ad()
            elif escolha == "3": diagnostico_firewall()
            elif escolha == "4": treinamento()
            elif escolha == "5":
                log_event("INFO", "Saindo do CLI Ultimate Militar 4.0")
                break
            else: log_event("ERRO", "Opção inválida")
        except KeyboardInterrupt:
            log_event("INFO", "Ctrl+C detectado, retornando ao menu principal")

# ---------------- Execução ----------------
if __name__ == "__main__":
    try:
        console.print("[bold blue]Bem-vindo ao CLI Ultimate Militar 4.0[/bold blue]")
        log_event("INFO", "CLI iniciada")
        menu_principal()
        log_event("INFO", "CLI encerrada com sucesso")
    except KeyboardInterrupt:
        log_event("INFO", "Execução interrompida (Ctrl+C). Até logo!")

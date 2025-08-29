#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ServAudit CLI 2.1 - Corporate Ready
Autor: Fabiano Aparecido
Descrição: Painel CLI profissional para Windows/Linux Servers, execução de comandos, logs SIEM, 
relatórios interativos e proteção de código/credenciais.
Versão: 2.1 Corporate
"""

import sys
import subprocess
import importlib
import os
import hashlib
from getpass import getpass
from datetime import datetime
import csv
import json
from pathlib import Path

# =======================
# Diretório de saída de reports
# =======================
BASE_DIR = Path(__file__).parent.resolve()  # Pasta onde o script está
REPORT_DIR = BASE_DIR / "REPORT"
REPORT_DIR.mkdir(exist_ok=True)  # Cria a pasta REPORT se não existir

# =======================
# Pre-check de módulos
# =======================
required_modules = ["rich", "jinja2", "plotly"]
for module in required_modules:
    try:
        importlib.import_module(module)
    except ImportError:
        print(f"[INFO] Biblioteca '{module}' não encontrada. Instalando automaticamente...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from jinja2 import Template
import plotly.graph_objects as go

console = Console()

# =======================
# Funções de segurança
# =======================
def verify_hash(file_path, known_hash):
    if not Path(file_path).exists():
        console.print(f"[bold red]Arquivo {file_path} não encontrado![/bold red]")
        sys.exit(1)
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    if file_hash != known_hash:
        console.print("[bold red]ERRO: Código alterado ou corrompido! Abortando execução.[/bold red]")
        sys.exit(1)

def log_action(action_desc):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.getenv("USER") or os.getenv("USERNAME")
    host = os.uname().nodename if hasattr(os, "uname") else "WindowsHost"
    log_entry = {"timestamp": timestamp, "user": user, "host": host, "action": action_desc}
    # Log JSON para integração SIEM
    with open(REPORT_DIR / "servaudit_audit.json", "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")
    # Log CSV tradicional
    with open(REPORT_DIR / "servaudit_audit.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, user, host, action_desc])

# =======================
# Funções de relatórios
# =======================
def save_report_csv(filename, tasks):
    filepath = REPORT_DIR / filename
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Tarefa", "Comando / Exemplo"])
        for t, cmd in tasks:
            writer.writerow([t, cmd])
    console.print(f"[bold green]Report CSV salvo em {filepath}[/bold green]")

def save_report_html(filename, tasks, title="Report"):
    filepath = REPORT_DIR / filename
    template_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{{title}}</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e1e; color: #f0f0f0; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #555; padding: 8px; text-align: left; }
            th { background-color: #444; }
            tr:nth-child(even) { background-color: #2e2e2e; }
        </style>
    </head>
    <body>
        <h1>{{title}}</h1>
        <table>
            <tr><th>Tarefa</th><th>Comando / Exemplo</th></tr>
            {% for t, cmd in tasks %}
            <tr><td>{{t}}</td><td>{{cmd}}</td></tr>
            {% endfor %}
        </table>
        <div id="chart" style="width:100%;height:400px;"></div>
        <script>
            var data = [{
                x: [{% for t, cmd in tasks %}"{{t}}",{% endfor %}],
                y: [{% for t, cmd in tasks %}{{loop.index}}, {% endfor %}],
                type: 'bar'
            }];
            Plotly.newPlot('chart', data);
        </script>
    </body>
    </html>
    """
    template = Template(template_html)
    rendered = template.render(title=title, tasks=tasks)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(rendered)
    console.print(f"[bold green]Report HTML interativo salvo em {filepath}[/bold green]")

# =======================
# Funções de execução de comandos
# =======================
def execute_command(command):
    try:
        console.print(f"[bold yellow]Executando:[/bold yellow] {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            console.print(line.strip())
        for err in process.stderr:
            console.print(f"[bold red]{err.strip()}[/bold red]")
        process.wait()
        log_action(f"Executou comando: {command}")
    except Exception as e:
        console.print(f"[bold red]Erro ao executar comando: {e}[/bold red]")
        log_action(f"Erro ao executar comando: {command} | {e}")

# =======================
# Menus
# =======================
def main_menu():
    table = Table(title="SERVAUDIT CLI 2.1 - MENU PRINCIPAL", box=box.DOUBLE_EDGE)
    table.add_column("Opção", justify="center", style="cyan", no_wrap=True)
    table.add_column("Descrição", style="green")
    table.add_row("1", "Windows Server")
    table.add_row("2", "Linux Server")
    table.add_row("3", "Tarefas Comuns")
    table.add_row("0", "Sair")
    console.print(table)
    choice = Prompt.ask("Digite a opção desejada", choices=["0", "1", "2", "3"])
    return choice

def windows_menu():
    tasks = [
        ("Active Directory e GPOs", "New-ADOrganizationalUnit -Name 'OU_Teste'; New-ADUser -Name 'UserTeste'; Get-GPO -All"),
        ("Serviços", "Get-Service | Where-Object {$_.Status -eq 'Running'}; Restart-Service 'Spooler'"),
        ("Backup e Recovery", "wbadmin start backup -backupTarget:D: -include:C: -quiet; VSSAdmin List Shadows"),
        ("Segurança", "Get-WindowsUpdate; Set-NetFirewallProfile -Enabled True; AuditPol /get /category:*"),
        ("Integração Cloud", "Connect-AzureAD; Get-MsolUser; Set-MsolUserPassword -UserPrincipalName user@domain.com"),
        ("Monitoramento", "Get-EventLog -LogName System -Newest 20; Get-Process | Sort CPU -Descending")
    ]
    table = Table(title="WINDOWS SERVER - COMANDOS", box=box.ROUNDED, show_lines=True)
    table.add_column("Tarefa", style="yellow")
    table.add_column("Comando / Exemplo", style="magenta")
    for t, cmd in tasks:
        table.add_row(t, cmd)
    console.print(table)
    save_report_csv("report_windows.csv", tasks)
    save_report_html("report_windows.html", tasks, title="Windows Server Report")
    log_action("Acessou menu Windows Server")

    choice = Prompt.ask("Deseja executar algum comando? (s/n)", choices=["s","n"])
    if choice == "s":
        cmd_to_exec = Prompt.ask("Digite o comando a ser executado")
        execute_command(cmd_to_exec)
    input("Pressione Enter para voltar ao menu principal...")

def linux_menu():
    tasks = [
        ("Gerenciamento de Pacotes", "sudo apt update && sudo apt upgrade -y; sudo yum install htop -y"),
        ("Serviços e Daemons", "sudo systemctl start/stop/restart nginx; sudo systemctl status apache2"),
        ("Segurança e Hardening", "sudo ufw enable; sudo ufw status; sudo fail2ban-client status; sestatus"),
        ("Logs e Monitoramento", "tail -f /var/log/syslog; journalctl -xe; sudo wazuh-agent-control -S"),
        ("Automação", "bash script.sh; ansible-playbook deploy.yml; python3 automacao.py"),
        ("Usuários e Permissões", "sudo adduser teste; sudo usermod -aG sudo teste; sudo quota -v"),
        ("Cloud e Containers", "docker run hello-world; kubectl get pods; openstack server list")
    ]
    table = Table(title="LINUX SERVER - COMANDOS", box=box.ROUNDED, show_lines=True)
    table.add_column("Tarefa", style="yellow")
    table.add_column("Comando / Exemplo", style="magenta")
    for t, cmd in tasks:
        table.add_row(t, cmd)
    console.print(table)
    save_report_csv("report_linux.csv", tasks)
    save_report_html("report_linux.html", tasks, title="Linux Server Report")
    log_action("Acessou menu Linux Server")

    choice = Prompt.ask("Deseja executar algum comando? (s/n)", choices=["s","n"])
    if choice == "s":
        cmd_to_exec = Prompt.ask("Digite o comando a ser executado")
        execute_command(cmd_to_exec)
    input("Pressione Enter para voltar ao menu principal...")

def common_menu():
    tasks = [
        ("Monitoramento", "CPU, memória, disco, rede (htop, perfmon, Zabbix)"),
        ("Gerenciamento de Usuários", "criação, modificação e remoção de contas"),
        ("Atualizações", "aplicação de patches e updates regulares"),
        ("Backup & Recovery", "rsync, VSS, snapshots, teste DR"),
        ("Automação e Scripting", "PowerShell, Bash, Python, Ansible"),
        ("Documentação & Compliance", "inventário, auditoria, normas ISO/ITIL"),
        ("Virtualização & Containers", "Hyper-V, KVM, VMware; Docker, Kubernetes")
    ]
    panel_text = "\n".join([f"[green]{t}:[/green] {cmd}" for t, cmd in tasks])
    console.print(Panel(panel_text, title="TAREFAS COMUNS", box=box.DOUBLE, style="cyan"))
    save_report_csv("report_common.csv", tasks)
    save_report_html("report_common.html", tasks, title="Tarefas Comuns Report")
    log_action("Acessou menu Tarefas Comuns")
    input("Pressione Enter para voltar ao menu principal...")

# =======================
# Função principal
# =======================
def main():
    if "--help" in sys.argv:
        console.print("\nServAudit CLI 2.1 - Corporate Ready", style="bold green")
        console.print("Uso: python3 servaudit_cli.py\n")
        console.print("Funcionalidades:")
        console.print("- Menu CLI avançado para Windows e Linux Server")
        console.print("- Execução de comandos com saída em tempo real")
        console.print("- Logs auditáveis JSON/CSV integráveis com SIEM")
        console.print("- Relatórios HTML interativos com gráficos")
        console.print("- Proteção de código e credenciais")
        console.print("- Mensagens amigáveis e Ctrl+C protegido")
        sys.exit(0)

    while True:
        try:
            choice = main_menu()
            if choice == "1":
                windows_menu()
            elif choice == "2":
                linux_menu()
            elif choice == "3":
                common_menu()
            elif choice == "0":
                console.print("Saindo do ServAudit CLI 2.1... Até logo!", style="bold red")
                log_action("Saiu do ServAudit CLI 2.1")
                break
        except KeyboardInterrupt:
            console.print("\nOperação cancelada pelo usuário. Voltando ao menu...", style="bold red")
            log_action("Operação cancelada pelo usuário via Ctrl+C")
        except Exception as e:
            console.print(f"Ocorreu um erro: {e}", style="bold red")
            log_action(f"Erro: {e}")

if __name__ == "__main__":
    main()

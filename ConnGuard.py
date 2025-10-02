#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConnMon - Monitoramento de Conexões em Tempo Real com Alertas
Autor: Fabiano (Exemplo Profissional)
"""

import os
import sys
import time
import json
import csv
import signal
import argparse
import subprocess
from datetime import datetime
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Confirm
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.align import Align

console = Console()

VERSION = "1.2.0"

# Configurações padrão
CONFIG = {
    "limite_conexoes": 50,         # limite para alerta
    "portas_sensiveis": [22, 3389], # SSH e RDP
    "intervalo": 3,                 # intervalo entre verificações (segundos)
    "saida_log": "connmon_log.json",
    "saida_csv": "connmon_log.csv",
    "saida_html": "connmon_log.html"
}

# Função para captura de conexões
def get_connections():
    try:
        result = subprocess.check_output(["ss", "-tunap"], stderr=subprocess.DEVNULL).decode()
        return result.splitlines()
    except Exception as e:
        console.print(f"[red]Erro ao coletar conexões: {e}[/red]")
        return []

# Função para salvar CSV
def save_csv(entry):
    file_exists = os.path.isfile(CONFIG["saida_csv"])
    with open(CONFIG["saida_csv"], "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["timestamp", "total", "alertas"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(entry)

# Função para salvar HTML simples
def save_html(entry):
    header = "<html><head><title>ConnMon Log</title></head><body><h1>Logs de Conexões</h1><table border='1'>"
    row = f"<tr><td>{entry['timestamp']}</td><td>{entry['total']}</td><td>{'<br>'.join(entry['alertas'])}</td></tr>"
    footer = "</table></body></html>"

    if not os.path.isfile(CONFIG["saida_html"]):
        with open(CONFIG["saida_html"], "w") as f:
            f.write(header + row + footer)
    else:
        with open(CONFIG["saida_html"], "r") as f:
            content = f.read()
        content = content.replace("</table></body></html>", row + "</table></body></html>")
        with open(CONFIG["saida_html"], "w") as f:
            f.write(content)

# Função que constrói o dashboard
def build_dashboard(conexoes, qtd, agora, alertas):
    layout = Layout()

    # Divisão da tela
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=5),
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )

    # Cabeçalho
    header_text = Text(f"📡 ConnMon - Monitoramento em Tempo Real | {agora}", style="bold cyan")
    layout["header"].update(Align.center(header_text))

    # Painel esquerdo → Tabela de conexões
    table = Table(title="🔎 Conexões Ativas", expand=True)
    table.add_column("Origem", style="cyan", no_wrap=True)
    table.add_column("Destino", style="green", no_wrap=True)
    table.add_column("Status", style="magenta", no_wrap=True)

    for c in conexoes[:10]:  # mostra só 10 para não poluir
        parts = c.split()
        if len(parts) >= 5:
            origem, destino, status = parts[4], parts[5], parts[1]
            table.add_row(origem, destino, status)

    layout["left"].update(Panel(table, title="🌍 Tráfego", border_style="blue"))

    # Painel direito → Estatísticas
    status_color = "green" if qtd <= CONFIG["limite_conexoes"] else "red"
    stats = Table.grid()
    stats.add_row("Total de conexões:", Text(str(qtd), style=f"bold {status_color}"))
    stats.add_row("Limite definido:", str(CONFIG["limite_conexoes"]))
    stats.add_row("Intervalo de verificação:", f"{CONFIG['intervalo']}s")
    stats.add_row("Portas sensíveis:", ", ".join(map(str, CONFIG["portas_sensiveis"])))

    # Top IPs
    ip_counter = Counter([c.split()[4].split(":")[0] for c in conexoes if len(c.split()) >= 5])
    top_ips = "\n".join([f"{ip} ({count})" for ip, count in ip_counter.most_common(5)])
    stats.add_row("Top IPs de origem:", top_ips if top_ips else "N/A")

    layout["right"].update(Panel(stats, title="📊 Estatísticas", border_style="yellow"))

    # Rodapé → Alertas recentes
    if alertas or qtd > CONFIG["limite_conexoes"]:
        footer_text = "\n".join([f"⚠ {a}" for a in alertas[-3:]]) or "⚠ Muitas conexões!"
        layout["footer"].update(Panel(footer_text, title="🚨 Alertas", border_style="red"))
    else:
        layout["footer"].update(Panel("✅ Nenhum alerta no momento", title="Status", border_style="green"))

    return layout

# Função de monitoramento com dashboard
def monitor():
    console.print("[bold cyan]\n🚀 Iniciando ConnMon Dashboard (CTRL+C para sair)[/bold cyan]")

    with Live(console=console, refresh_per_second=2, screen=True) as live:
        while True:
            lines = get_connections()
            conexoes = [l for l in lines if "ESTAB" in l]

            qtd = len(conexoes)
            agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alertas = []

            # Verifica portas sensíveis
            for c in conexoes:
                for porta in CONFIG["portas_sensiveis"]:
                    if f":{porta}" in c:
                        parts = c.split()
                        if len(parts) >= 5:
                            origem, destino = parts[4], parts[5]
                            alertas.append(f"Conexão suspeita → {origem} -> {destino} (porta {porta})")

            # Salva logs
            log_entry = {"timestamp": agora, "total": qtd, "alertas": alertas}
            with open(CONFIG["saida_log"], "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            save_csv(log_entry)
            save_html(log_entry)

            # Renderiza dashboard
            live.update(build_dashboard(conexoes, qtd, agora, alertas))

            time.sleep(CONFIG["intervalo"])

# Sair graciosamente
def handle_exit(sig, frame):
    console.print("\n[bold red]🛑 Monitoramento encerrado pelo usuário[/bold red]")
    sys.exit(0)

# Menu principal
def main():
    parser = argparse.ArgumentParser(description="Monitoramento de Conexões em Tempo Real")
    parser.add_argument("--version", action="store_true", help="Mostra versão do programa")
    parser.add_argument("--helpme", action="store_true", help="Exibe exemplos de uso")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso (logs apenas)")
    args = parser.parse_args()

    if args.version:
        console.print(f"ConnMon versão {VERSION}")
        sys.exit(0)

    if args.helpme:
        console.print("""
        Exemplos de uso:
        ▶ python connmon.py              → inicia monitoramento interativo
        ▶ python connmon.py --quiet      → somente gera logs sem interface
        ▶ python connmon.py --version    → mostra versão

        Logs disponíveis em:
        - JSON: connmon_log.json
        - CSV:  connmon_log.csv
        - HTML: connmon_log.html
        """)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    if Confirm.ask("Deseja iniciar o monitoramento agora?"):
        monitor()
    else:
        console.print("[yellow]Operação cancelada pelo usuário.[/yellow]")

if __name__ == "__main__":
    main()

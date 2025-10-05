#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysAudit Pro v4.0 – Versão Final Ultra-Profissional
Autor: Fabiano Aparecido
Descrição: Auditoria corporativa avançada de sistemas, rede, usuários e processos.
Modo interativo ou silencioso. Exportação detalhada JSON/CSV.
Compatível Windows, Linux, MacOS.
"""

import os
import sys
import platform
import json
import csv
from pathlib import Path
from datetime import datetime
from threading import Thread, Lock
from time import sleep
import argparse

# ----------------------------------------------------------
# Rich para UI Profissional
# ----------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.logging import RichHandler
    import logging
except ImportError:
    print("Instalando dependências Rich...")
    os.system("pip install rich")
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.logging import RichHandler
    import logging

console = Console()
lock = Lock()

# ----------------------------------------------------------
# Logging avançado com cores
# ----------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console)]
)
log = logging.getLogger("SysAuditPro")

# ----------------------------------------------------------
# Utilitários
# ----------------------------------------------------------
def create_reports_folder():
    Path("reports").mkdir(exist_ok=True)

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_report(data, category, fmt="json"):
    create_reports_folder()
    file_path = Path(f"reports/{category}_{timestamp()}.{fmt}")
    try:
        if fmt == "json":
            with open(file_path, "w") as f:
                json.dump(data, f, indent=4)
        else:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if isinstance(data, dict):
                    for key, value in data.items():
                        writer.writerow([key, value])
                else:
                    for line in data:
                        writer.writerow([line])
        log.info(f"Relatório '{category}' exportado: {file_path}")
    except Exception as e:
        log.error(f"Falha ao exportar relatório '{category}': {e}")

# ----------------------------------------------------------
# Coletas
# ----------------------------------------------------------
def collect_system_info():
    try:
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.architecture()[0],
            "uptime": os.popen("uptime").read().strip() if platform.system() != "Windows" else os.popen("net stats srv").read().strip()
        }
    except Exception as e:
        log.error(f"Falha na coleta de sistema: {e}")
        return {}

def collect_users():
    try:
        if platform.system() == "Windows":
            return os.popen("query user").read().strip().splitlines()
        else:
            return os.popen("who").read().strip().splitlines()
    except Exception as e:
        log.error(f"Falha na coleta de usuários: {e}")
        return []

def collect_network():
    try:
        if platform.system() == "Windows":
            return os.popen("netstat -ano").read().strip().splitlines()
        else:
            return os.popen("netstat -tulnp").read().strip().splitlines()
    except Exception as e:
        log.error(f"Falha na coleta de rede: {e}")
        return []

def collect_processes_services():
    try:
        if platform.system() == "Windows":
            procs = os.popen("tasklist").read().strip().splitlines()
            services = os.popen("sc query type= service state= all").read().strip().splitlines()
        else:
            procs = os.popen("ps aux").read().strip().splitlines()
            services = os.popen("systemctl list-units --type=service --state=running").read().strip().splitlines()
        return {"processes": procs, "services": services}
    except Exception as e:
        log.error(f"Falha na coleta de processos/serviços: {e}")
        return {"processes": [], "services": []}

# ----------------------------------------------------------
# Threaded Collection com barra de progresso detalhada
# ----------------------------------------------------------
def threaded_collection(functions, silent=False):
    results = {}
    threads = []

    def worker(name, func):
        if not silent:
            log.info(f"Coletando {name}...")
        results[name] = func()
        if not silent:
            log.info(f"{name} finalizado.")

    for name, func in functions.items():
        t = Thread(target=worker, args=(name, func))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results

# ----------------------------------------------------------
# Menu interativo com dark mode
# ----------------------------------------------------------
def interactive_menu(default_format="json"):
    while True:
        console.print("\n[bold magenta]=== Menu Principal SysAudit Pro v4.0 ===[/bold magenta]")
        console.print("[cyan]1.[/cyan] Coletar Sistema Completo")
        console.print("[cyan]2.[/cyan] Coletar Usuários Logados")
        console.print("[cyan]3.[/cyan] Coletar Conexões de Rede")
        console.print("[cyan]4.[/cyan] Coletar Processos e Serviços")
        console.print("[cyan]5.[/cyan] Sair")

        choice = console.input("[bold yellow]Escolha uma opção:[/bold yellow] ")

        if choice == "1":
            functions = {
                "system_info": collect_system_info,
                "users": collect_users,
                "network": collect_network,
                "processes_services": collect_processes_services
            }
            with Progress(
                SpinnerColumn(),
                BarColumn(),
                TextColumn("{task.description}"),
                TimeElapsedColumn(),
                TimeRemainingColumn()
            ) as progress:
                task = progress.add_task("Coletando sistema completo...", total=None)
                report = threaded_collection(functions)
                progress.remove_task(task)
            for key, data in report.items():
                save_report(data, key, fmt=default_format)

        elif choice == "2":
            report = collect_users()
            save_report(report, "users", fmt=default_format)
        elif choice == "3":
            report = collect_network()
            save_report(report, "network", fmt=default_format)
        elif choice == "4":
            report = collect_processes_services()
            for key, data in report.items():
                save_report(data, key, fmt=default_format)
        elif choice == "5":
            console.print("[bold green]Saindo do SysAudit Pro...[/bold green]")
            sys.exit(0)
        else:
            log.warning("Opção inválida! Tente novamente.")

# ----------------------------------------------------------
# Função principal
# ----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SysAudit Pro 4.0 – Auditoria Corporativa Avançada")
    parser.add_argument("--version", action="version", version="SysAudit Pro 4.0")
    parser.add_argument("--format", type=str, choices=["json", "csv"], default="json",
                        help="Formato de exportação padrão (json ou csv)")
    parser.add_argument("--silent", action="store_true",
                        help="Executa modo silencioso sem interatividade, ideal para automação e CI/CD")
    args = parser.parse_args()

    console.print("[bold cyan]=== SysAudit Pro v4.0 – Ultra-Profissional ===[/bold cyan]")

    if args.silent:
        log.info("Executando em modo silencioso...")
        functions = {
            "system_info": collect_system_info,
            "users": collect_users,
            "network": collect_network,
            "processes_services": collect_processes_services
        }
        report = threaded_collection(functions, silent=True)
        for key, data in report.items():
            save_report(data, key, fmt=args.format)
        log.info("Coleta silenciosa finalizada com sucesso.")
    else:
        interactive_menu(default_format=args.format)

if __name__ == "__main__":
    main()

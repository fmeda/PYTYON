#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AppGuardianX v2.0.0 - CMNI Corporativo Avançado
Controle, Monitoramento, Notificação e Isolamento de Aplicações
Autor: Fabiano Aparecido
"""
import typer, psutil, subprocess, asyncio, os, json, aiofiles
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime

app = typer.Typer(help="AppGuardianX CMNI Corporativo Avançado")
console = Console()
LOG_FILE = "/var/log/appguardianx_log.json"
CGROUP_PATH = "/sys/fs/cgroup/appguardianx"

# ---------- FUNÇÕES DE LOG ----------
async def save_log(event: str, data: dict):
    log_entry = {"timestamp": datetime.now().isoformat(), "event": event, "details": data}
    async with aiofiles.open(LOG_FILE, mode="a") as f:
        await f.write(json.dumps(log_entry) + "\n")

# ---------- FUNÇÃO DE ALERTA ----------
def alert_check(cpu_usage: float, threshold: int):
    if cpu_usage > threshold:
        console.print(f"[bold red]⚠ ALERTA:[/bold red] CPU acima do limite! ({cpu_usage}%)")
        asyncio.create_task(save_log("alert_cpu_threshold", {"cpu_usage": cpu_usage, "threshold": threshold}))

# ---------- FUNÇÃO DE ISOLAMENTO REAL ----------
def setup_sandbox(app_path: str, cpu_limit: int, mem_limit: int):
    """
    Cria cgroup e namespace isolado para a aplicação.
    """
    os.makedirs(CGROUP_PATH, exist_ok=True)
    cpu_cgroup = os.path.join(CGROUP_PATH, "cpu")
    mem_cgroup = os.path.join(CGROUP_PATH, "memory")
    os.makedirs(cpu_cgroup, exist_ok=True)
    os.makedirs(mem_cgroup, exist_ok=True)

    # Limites de CPU e memória
    with open(os.path.join(cpu_cgroup, "cpu.max"), "w") as f:
        f.write(f"{cpu_limit * 1000} 100000\n")  # cgroups v2 CPU quota
    with open(os.path.join(mem_cgroup, "memory.max"), "w") as f:
        f.write(f"{mem_limit * 1024 * 1024}\n")  # memória em bytes

    # Executa em namespace isolado (PID, mount)
    pid = subprocess.Popen(["unshare", "--fork", "--pid", "--mount-proc", app_path])
    return pid

# ---------- COMANDO ISOLATE ----------
@app.command()
def isolate(
    process_path: str = typer.Argument(..., help="Caminho da aplicação a isolar"),
    cpu_limit: int = typer.Option(50, "--cpu", help="Limite CPU (%)"),
    mem_limit: int = typer.Option(512, "--mem", help="Limite memória (MB)"),
):
    """Isola aplicação usando namespaces e cgroups"""
    if not os.path.exists(process_path):
        console.print(f"[bold red]❌ Erro:[/bold red] Caminho inválido: {process_path}")
        return

    console.print(f"[cyan]🔒 Iniciando isolamento avançado para:[/cyan] {process_path}")
    asyncio.run(save_log("isolation_start", {"app": process_path, "cpu": cpu_limit, "mem": mem_limit}))

    if not typer.confirm("Deseja realmente aplicar limites e isolar esta aplicação?"):
        console.print("[yellow]⚠ Operação cancelada pelo usuário.[/yellow]")
        return

    pid = setup_sandbox(process_path, cpu_limit, mem_limit)
    console.print(f"[green]✔ Aplicação isolada com sucesso! PID: {pid.pid}[/green]")
    asyncio.run(save_log("isolation_complete", {"app": process_path, "pid": pid.pid}))

# ---------- COMANDO MONITOR ----------
@app.command()
def monitor(threshold: int = typer.Option(80, "--threshold", help="Alerta de CPU (%)")):
    """Monitora todos os processos ativos e aplica CMNI"""
    table = Table(title="Monitoramento CMNI", show_lines=True)
    table.add_column("PID", justify="center")
    table.add_column("Nome", justify="left")
    table.add_column("CPU (%)", justify="center")
    table.add_column("Memória (MB)", justify="center")

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
            table.add_row(str(proc.info['pid']), proc.info['name'], str(proc.info['cpu_percent']), f"{mem_mb:.1f}")
            alert_check(proc.info['cpu_percent'], threshold)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    console.print(table)
    asyncio.run(save_log("monitor_update", {"active_processes": len(psutil.pids())}))

# ---------- COMANDO AUDIT ----------
@app.command()
def audit(output: str = typer.Option("/var/log/appguardianx_audit.json", "--output")):
    """Gera relatório completo de auditoria"""
    if not os.path.exists(LOG_FILE):
        console.print("[yellow]⚠ Nenhum log encontrado.[/yellow]")
        return

    with open(LOG_FILE) as f:
        logs = [json.loads(line) for line in f]

    with open(output, "w") as out:
        json.dump(logs, out, indent=4)

    console.print(f"[green]✔ Auditoria salva em {output}[/green]")
    asyncio.run(save_log("audit_report_generated", {"output": output}))

if __name__ == "__main__":
    app()

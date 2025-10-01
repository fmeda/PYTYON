#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ThreatIntel Fusion CLI (TIF-CLI)
Script de Integração com VirusTotal + Shodan — CMNI Enhanced (versão 3.1)

Recursos principais:
 - Instalação/verificação automática de dependências
 - Proteção avançada de credenciais (ENV, keyring, getpass)
 - Sanitização de logs/erros para evitar vazamento de tokens
 - Cache local SQLite opcional
 - Tratamento gracioso de Ctrl+C (SIGINT)
 - UX aprimorada com rich / tqdm (cores, tabelas, progresso)
 - Saída em JSON/CSV e resumo executivo
 - --help avançado, multilíngue básico (pt/en), --version
"""

from __future__ import annotations
import os
import sys
import re
import json
import csv
import time
import signal
import sqlite3
import logging
import argparse
import subprocess
import getpass
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ----------------------------
# Minimal args to decide auto-install behavior before heavy imports
# ----------------------------
MINIMAL_PARSER = argparse.ArgumentParser(add_help=False)
MINIMAL_PARSER.add_argument("--no-install", action="store_true", help="Não instalar dependências automaticamente")
MINIMAL_PARSER.add_argument("--yes", action="store_true", help="Assume yes nas confirmações (não interativo)")
_known_min_args, _ = MINIMAL_PARSER.parse_known_args()

# ----------------------------
# Dependencies list (module_name, pip_name)
# ----------------------------
REQUIRED_PACKAGES = [
    ("requests", "requests"),
    ("dateutil", "python-dateutil"),
    ("tqdm", "tqdm"),
    ("tabulate", "tabulate"),
    ("keyring", "keyring"),
    ("rich", "rich"),
]

def install_package(pkg_name: str):
    """Instala um pacote via pip usando o mesmo interpretador python."""
    print(f"[installer] Instalando {pkg_name} ...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])

def precheck_and_install(auto_install: bool = True, assume_yes: bool = False):
    """
    Tenta importar cada módulo; se faltar, tenta instalar (se auto_install True).
    """
    missing = []
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
        except Exception:
            missing.append((import_name, pip_name))
    if not missing:
        return
    names = ", ".join(p[0] for p in missing)
    print(f"[installer] Dependências faltando: {names}")
    if not auto_install:
        print("[installer] Instalação automática desabilitada. Saia e instale manualmente.")
        sys.exit(2)
    for import_name, pip_name in missing:
        if not assume_yes:
            answer = input(f"Instalar {pip_name}? [Y/n] ").strip().lower() or "y"
            if answer not in ("y", "yes"):
                print(f"[installer] Usuário optou por não instalar {pip_name}. Abortando.")
                sys.exit(3)
        install_package(pip_name)

# Run precheck (respects user's --no-install/--yes minimal flags)
precheck_and_install(auto_install=not _known_min_args.no_install, assume_yes=_known_min_args.yes)

# Now safe to import extras
import requests
from dateutil import parser as dateparser
from tqdm import tqdm
from tabulate import tabulate
import keyring
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

# ----------------------------
# Logging (technical; sanitized)
# ----------------------------
LOG_FILE = "tif_cli_analysis.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
# reduce noisy logs
logging.getLogger("requests").setLevel(logging.WARNING)

# ----------------------------
# Globals / constants
# ----------------------------
USER_AGENT = "ThreatIntel-Fusion-CLI/3.1"
CACHE_DB = "tif_cli_cache.db"
SENSITIVE_KEYS_PATTERN = re.compile(r"[A-Za-z0-9\-\_]{16,}")  # heuristic for long tokens
SHUTDOWN = False

# ----------------------------
# Signal handling (Ctrl+C)
# ----------------------------
def sigint_handler(signum, frame):
    global SHUTDOWN
    SHUTDOWN = True
    console.print("\n[yellow]⚠️  Recebido SIGINT (Ctrl+C). Finalizando graciosamente...[/yellow]")
    raise KeyboardInterrupt()

signal.signal(signal.SIGINT, sigint_handler)

# ----------------------------
# Sanitization / credential protection
# ----------------------------
def mask_key(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}{'*' * max(4, len(s)-8)}{s[-4:]}"

def sanitize_message(msg: str) -> str:
    if not msg:
        return msg
    return SENSITIVE_KEYS_PATTERN.sub(lambda m: mask_key(m.group(0)), msg)

def safe_log_exception(exc: Exception, context: str = ""):
    logging.error("[%s] %s", context, sanitize_message(str(exc)))

# ----------------------------
# Credential retrieval policy
# ----------------------------
def get_api_key(name: str, env_var: str, service_keyring: Optional[str] = None, assume_yes: bool = False) -> Optional[str]:
    # 1) env var
    v = os.getenv(env_var)
    if v:
        console.print(f"[green]{name}[/green] carregado via ENV (mascarado={mask_key(v)})")
        return v
    # 2) keyring
    try:
        if service_keyring:
            kr = keyring.get_password(service_keyring, name)
            if kr:
                console.print(f"[green]{name}[/green] recuperado via keyring (mascarado={mask_key(kr)})")
                return kr
    except Exception as e:
        safe_log_exception(e, "keyring_get")
    # 3) prompt secure
    try:
        v = getpass.getpass(f"Insira {name} (entrada oculta): ")
        if not v:
            console.print(f"[yellow]Nenhuma {name} fornecida.[/yellow]")
            return None
        if service_keyring:
            store = "y" if assume_yes else input("Gravar esta credencial no keyring do sistema? [y/N] ").strip().lower()
            if store in ("y", "yes"):
                try:
                    keyring.set_password(service_keyring, name, v)
                    console.print(f"[green]{name} gravado no keyring local.[/green]")
                except Exception as e:
                    safe_log_exception(e, "keyring_set")
                    console.print("[yellow]Falha ao gravar no keyring; continuando sem gravar.[/yellow]")
        return v
    except Exception as e:
        safe_log_exception(e, "get_api_key_prompt")
        return None

# ----------------------------
# HTTP helper w/ simple rate-limit handling
# ----------------------------
def safe_get(url: str, headers: Dict[str, str], params: Dict[str, Any] = None, timeout: int = 15) -> requests.Response:
    for attempt in range(1, 6):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        except Exception as e:
            safe_log_exception(e, "http_get")
            raise
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", 2 ** attempt))
            console.print(f"[yellow]Rate limited. Backoff {wait}s ({url}).[/yellow]")
            time.sleep(wait)
            continue
        return resp
    resp.raise_for_status()
    return resp

# ----------------------------
# VirusTotal helpers (v3)
# ----------------------------
def vt_headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key, "User-Agent": USER_AGENT}

def query_vt_ip(api_key: str, ip: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    resp = safe_get(url, headers=vt_headers(api_key))
    if resp.status_code == 200:
        return {"source": "virustotal", "type": "ip", "ip": ip, "data": resp.json()}
    elif resp.status_code == 404:
        return {"source": "virustotal", "type": "ip", "ip": ip, "data": None}
    else:
        return {"source": "virustotal", "type": "ip", "ip": ip, "error": sanitize_message(resp.text), "status": resp.status_code}

def query_vt_domain(api_key: str, domain: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = safe_get(url, headers=vt_headers(api_key))
    if resp.status_code == 200:
        return {"source": "virustotal", "type": "domain", "domain": domain, "data": resp.json()}
    elif resp.status_code == 404:
        return {"source": "virustotal", "type": "domain", "domain": domain, "data": None}
    else:
        return {"source": "virustotal", "type": "domain", "domain": domain, "error": sanitize_message(resp.text), "status": resp.status_code}

# ----------------------------
# Shodan helpers (direct HTTP)
# ----------------------------
def shodan_headers() -> Dict[str, str]:
    return {"User-Agent": USER_AGENT}

def query_shodan_ip(api_key: str, ip: str) -> Dict[str, Any]:
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    resp = safe_get(url, headers=shodan_headers(), params=params)
    if resp.status_code == 200:
        return {"source": "shodan", "type": "ip", "ip": ip, "data": resp.json()}
    elif resp.status_code == 404:
        return {"source": "shodan", "type": "ip", "ip": ip, "data": None}
    else:
        return {"source": "shodan", "type": "ip", "ip": ip, "error": sanitize_message(resp.text), "status": resp.status_code}

# ----------------------------
# Cache SQLite
# ----------------------------
def init_cache(dbpath: str = CACHE_DB):
    conn = sqlite3.connect(dbpath, timeout=10)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            target TEXT PRIMARY KEY,
            result TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def get_from_cache(target: str, dbpath: str = CACHE_DB) -> Optional[Dict[str, Any]]:
    try:
        conn = sqlite3.connect(dbpath, timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT result FROM cache WHERE target = ?", (target,))
        row = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        safe_log_exception(e, "cache_read")
    return None

def save_to_cache(target: str, result: Dict[str, Any], dbpath: str = CACHE_DB):
    try:
        conn = sqlite3.connect(dbpath, timeout=10)
        cur = conn.cursor()
        cur.execute("REPLACE INTO cache (target, result) VALUES (?, ?)", (target, json.dumps(result)))
        conn.commit()
        conn.close()
    except Exception as e:
        safe_log_exception(e, "cache_write")

# ----------------------------
# Helpers gerais
# ----------------------------
def is_ip(target: str) -> bool:
    parts = target.split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def normalize_target(t: str) -> str:
    t = t.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return urlparse(t).netloc or t
    return t

# ----------------------------
# Orchestrator
# ----------------------------
def analyze_target(target: str, vt_key: Optional[str], sh_key: Optional[str], use_cache: bool = True) -> Dict[str, Any]:
    t = normalize_target(target)
    out: Dict[str, Any] = {"target": t, "is_ip": is_ip(t), "vt": None, "shodan": None, "errors": []}
    if SHUTDOWN:
        out["errors"].append("shutdown_in_progress")
        return out

    if use_cache:
        cached = get_from_cache(t)
        if cached:
            cached["_cached"] = True
            return cached

    try:
        if is_ip(t):
            if vt_key:
                try:
                    out["vt"] = query_vt_ip(vt_key, t)
                except Exception as e:
                    safe_log_exception(e, "vt_ip")
                    out["errors"].append("vt_ip_exception")
            else:
                out["errors"].append("vt_no_key")

            if sh_key:
                try:
                    out["shodan"] = query_shodan_ip(sh_key, t)
                except Exception as e:
                    safe_log_exception(e, "shodan_ip")
                    out["errors"].append("shodan_ip_exception")
            else:
                out["errors"].append("shodan_no_key")
        else:
            if vt_key:
                try:
                    out["vt"] = query_vt_domain(vt_key, t)
                except Exception as e:
                    safe_log_exception(e, "vt_domain")
                    out["errors"].append("vt_domain_exception")
            else:
                out["errors"].append("vt_no_key")
    except KeyboardInterrupt:
        out["errors"].append("interrupted")
    except Exception as e:
        safe_log_exception(e, f"analyze_target_{t}")
        out["errors"].append("unhandled_exception")
    finally:
        if use_cache:
            try:
                save_to_cache(t, out)
            except Exception:
                pass
    return out

# ----------------------------
# Export / Presentation
# ----------------------------
def export_json(results: List[Dict[str, Any]], outpath: str):
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    console.print(f"[green]Exportado JSON -> {outpath}[/green]")

def export_csv(results: List[Dict[str, Any]], outpath: str):
    fieldnames = [
        "target", "is_ip",
        "vt_malicious_votes", "vt_last_analysis_date", "vt_reputation",
        "shodan_org", "shodan_os", "shodan_ports", "errors", "_cached"
    ]
    rows = []
    for r in results:
        vt = r.get("vt", {}) or {}
        vt_data = vt.get("data") if isinstance(vt.get("data"), dict) else None
        vt_reputation = vt_data.get("attributes", {}).get("reputation") if vt_data else None
        vt_last = vt_data.get("attributes", {}).get("last_analysis_date") if vt_data else None
        vt_malicious_votes = None
        try:
            if vt_data:
                stats = vt_data.get("attributes", {}).get("last_analysis_stats") or {}
                vt_malicious_votes = stats.get("malicious") if isinstance(stats, dict) else None
        except Exception:
            vt_malicious_votes = None

        sh = r.get("shodan", {}) or {}
        sh_data = sh.get("data") if isinstance(sh.get("data"), dict) else None
        rows.append({
            "target": r.get("target"),
            "is_ip": r.get("is_ip"),
            "vt_malicious_votes": vt_malicious_votes,
            "vt_last_analysis_date": dateparser.parse(str(vt_last)).isoformat() if vt_last else None,
            "vt_reputation": vt_reputation,
            "shodan_org": sh_data.get("org") if sh_data else None,
            "shodan_os": sh_data.get("os") if sh_data else None,
            "shodan_ports": json.dumps(sh_data.get("ports")) if sh_data and sh_data.get("ports") else None,
            "errors": json.dumps(r.get("errors", []), ensure_ascii=False),
            "_cached": r.get("_cached", False)
        })
    with open(outpath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    console.print(f"[green]Exportado CSV -> {outpath}[/green]")

def print_executive_summary(results: List[Dict[str, Any]]):
    table = []
    for r in results:
        vt = r.get("vt", {}).get("data", {}).get("attributes", {}) if r.get("vt") else {}
        votes = vt.get("last_analysis_stats", {}).get("malicious", 0) if vt else 0
        rep = vt.get("reputation", 0) if vt else 0
        sh_org = r.get("shodan", {}).get("data", {}).get("org") if r.get("shodan") and r.get("shodan").get("data") else "N/A"
        table.append((r.get("target"), votes, rep, sh_org))
    table.sort(key=lambda x: (x[1] or 0), reverse=True)
    top = table[:10]
    console.print("\n[bold]Resumo executivo (top 10 por votos maliciosos):[/bold]")
    t = Table()
    t.add_column("Target", style="cyan")
    t.add_column("Malicious votes", style="red")
    t.add_column("Reputation", style="yellow")
    t.add_column("Shodan Org", style="green")
    for row in top:
        t.add_row(str(row[0]), str(row[1]), str(row[2]), str(row[3]))
    console.print(t)

# ----------------------------
# MAIN (replaced to avoid argparse ugly error)
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="ThreatIntel Fusion CLI (TIF-CLI)",
        description="Script de Integração com VirusTotal/Shodan para Análise de IOCs",
        epilog="Exemplo: python ThreatIntel_Fusion_CLI.py 8.8.8.8"
    )

    # Tornamos 'target' opcional para controlar a mensagem de erro manualmente
    parser.add_argument("target", nargs="?", help="IP ou domínio a ser analisado (ex: 8.8.8.8, example.com)")
    parser.add_argument("--targets", nargs="+", help="Lista de IPs/Domínios para análise (alternativa ao positional)")
    parser.add_argument("--output", "-o", help="Formato de saída (json/csv)", default="json")
    parser.add_argument("--lang", help="Idioma (pt/en)", default="pt")
    parser.add_argument("--version", action="store_true", help="Exibir versão do programa")
    parser.add_argument("--help-advanced", action="store_true", help="Exibir ajuda avançada com exemplos")
    parser.add_argument("--no-cache", action="store_true", help="Desabilita uso de cache SQLite")
    parser.add_argument("--no-install", action="store_true", help="Não instalar dependências automaticamente (pre-check)")
    parser.add_argument("--yes", action="store_true", help="Assume 'yes' nas confirmações (não interativo)")
    parser.add_argument("--workers", "-w", type=int, default=4, help="Threads concorrentes")
    args = parser.parse_args()

    if args.version:
        console.print("ThreatIntel Fusion CLI (TIF-CLI) - Versão 3.1 (CMNI Recruiter Edition)")
        sys.exit(0)

    if args.help_advanced:
        console.print("""
Ajuda Avançada - ThreatIntel Fusion CLI (TIF-CLI)

Exemplos:
  - analisar um único target (modo interativo):
      python ThreatIntel_Fusion_CLI.py 8.8.8.8

  - analisar múltiplos targets (modo não interativo):
      python ThreatIntel_Fusion_CLI.py --targets 8.8.8.8 example.com 1.2.3.4

  - gerar relatório CSV:
      python ThreatIntel_Fusion_CLI.py example.com --output csv

  - usar em pipelines (quiet mode / sem prompts):
      export VT_API_KEY="xxx"; export SHODAN_API_KEY="yyy"
      python ThreatIntel_Fusion_CLI.py example.com --output json --lang en

Observação:
  - Você pode informar o token via variáveis de ambiente VT_API_KEY e SHODAN_API_KEY
  - Em falta de credenciais, o programa solicitará entrada oculta (getpass)
""")
        sys.exit(0)

    # Normalize targets
    targets: List[str] = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        targets = args.targets

    # If no targets, show friendly usage examples and exit
    if not targets:
        console.print("\n[bold red]Nenhum target informado.[/bold red]")
        console.print("[yellow]Exemplo de comando (modo simples):[/yellow]")
        console.print("[green]  python ThreatIntel_Fusion_CLI.py 8.8.8.8[/green]")
        console.print("[yellow]Ou analisar múltiplos targets:[/yellow]")
        console.print("[green]  python ThreatIntel_Fusion_CLI.py --targets 8.8.8.8 example.com 1.2.3.4[/green]")
        console.print("\nUse [bold]--help-advanced[/bold] para mais exemplos.\n")
        sys.exit(1)

    # Respect no-install flag (re-run precheck to honor possible CLI override)
    precheck_and_install(auto_install=not args.no_install, assume_yes=args.yes)

    # Credential policy: ENV -> keyring -> prompt
    vt_key = get_api_key("VT_API_KEY", "VT_API_KEY", service_keyring="tif_cli", assume_yes=args.yes)
    sh_key = get_api_key("SHODAN_API_KEY", "SHODAN_API_KEY", service_keyring="tif_cli", assume_yes=args.yes)
    if not vt_key and not sh_key:
        console.print("[red]Nenhuma credencial VT/SHODAN disponível. Saindo.[/red]")
        sys.exit(4)

    use_cache = not args.no_cache
    if use_cache:
        try:
            init_cache()
            console.print(f"[green]Cache SQLite inicializado ({CACHE_DB})[/green]")
        except Exception as e:
            safe_log_exception(e, "init_cache")
            console.print("[yellow]Falha ao inicializar cache (continuando sem cache).[/yellow]")
            use_cache = False

    # Executor for concurrency
    workers = max(1, args.workers)
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {executor.submit(analyze_target, t, vt_key, sh_key, use_cache): t for t in targets}

    # Progress UI
    pbar = None
    try:
        if len(futures) > 1:
            pbar = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn())
            task = pbar.add_task("Scanning", total=len(futures))
            pbar.start()
        results: List[Dict[str, Any]] = []
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.append(res)
            except KeyboardInterrupt:
                console.print("[yellow]Interrompido pelo usuário. Coletando resultados parciais...[/yellow]")
                break
            except Exception as e:
                safe_log_exception(e, "future_result")
                results.append({"target": futures.get(fut), "errors": ["future_exception"]})
            if pbar:
                pbar.update(task, advance=1)
            if SHUTDOWN:
                console.print("[yellow]Shutdown requisitado — saindo do loop principal.[/yellow]")
                break
    finally:
        if pbar:
            pbar.stop()
        executor.shutdown(wait=False)

    # Export and summary
    try:
        if args.output.lower() == "csv" or args.output.lower().endswith(".csv"):
            outpath = "results.csv" if not args.output.lower().endswith(".csv") else args.output
            export_csv(results, outpath)
        else:
            outpath = "results.json" if not args.output.lower().endswith(".json") else args.output
            export_json(results, outpath)
    except Exception as e:
        safe_log_exception(e, "export")
        console.print("[red]Falha ao exportar resultados (veja logs sanitizados).[/red]")

    try:
        print_executive_summary(results)
    except Exception as e:
        safe_log_exception(e, "summary")
        console.print("[yellow]Falha ao gerar resumo executivo.[/yellow]")

    console.print("\n[green]Análise concluída.[/green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Execução interrompida pelo usuário (KeyboardInterrupt). Saindo.[/yellow]")
        sys.exit(1)
    except Exception as e:
        safe_log_exception(e, "main")
        console.print("[red]Um erro fatal ocorreu. Consulte o arquivo de log (mensagens sanitizadas).[/red]")
        sys.exit(2)

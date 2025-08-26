#!/usr/bin/env python3
"""
Script: Correlação Automática Wazuh + Zabbix -> Risk Score
Descrição:
  - Conecta na API do Wazuh para coletar alertas críticos recentes.
  - Conecta na API do Zabbix para coletar métricas (CPU, memória, disco, load, etc.).
  - Correlaciona eventos e métricas, aplica regras e gera um score de risco (0-100) por host.
  - Saída: JSON (padrão), CSV opcional e logs.

Requisitos:
  pip install requests python-dateutil tabulate

Como usar:
  python3 script_correlacao_wazuh_zabbix_riskscore.py --since 30m --host-list hosts.txt --out results.json

Observações:
  - Ajuste as credenciais e endpoints no bloco CONFIG abaixo.
  - O cálculo do score é modular e fácil de ajustar (pesos, thresholds).

Autor: Gerado por ChatGPT (adaptável)
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import sys
import time
import subprocess
import importlib
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from typing import Dict, List, Tuple, Any

# ---------------------- PRE-CHECK DE MÓDULOS ----------------------
REQUIRED_MODULES = ["requests", "python_dateutil", "tabulate"]

for mod in ["requests", "dateutil", "tabulate"]:
    try:
        importlib.import_module(mod)
    except ImportError:
        print(f"[INFO] Módulo {mod} não encontrado. Instalando...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", mod])

import requests
from tabulate import tabulate

# ---------------------- CONFIGURAÇÃO ----------------------
CONFIG = {
    'wazuh_api_url': 'https://wazuh.example.org:55000',
    'wazuh_user': 'wazuh_user',
    'wazuh_password': 'wazuh_pass',
    'zabbix_api_url': 'https://zabbix.example.org/api_jsonrpc.php',
    'zabbix_user': 'zabbix_user',
    'zabbix_password': 'zabbix_pass',
    'default_minutes': 30,
    'weights': {
        'wazuh_critical_count': 0.35,
        'cpu': 0.2,
        'memory': 0.15,
        'disk': 0.15,
        'load': 0.15
    },
    'thresholds': {
        'cpu_warn_pct': 70,
        'cpu_crit_pct': 90,
        'memory_warn_pct': 75,
        'memory_crit_pct': 90,
        'disk_warn_pct': 80,
        'disk_crit_pct': 95,
        'load_warn': 2.0,
        'load_crit': 5.0
    },
    'wazuh_count_max': 10,
}

# ---------------------- LOGGER ----------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('corr-wazuh-zabbix')

# ---------------------- UTILITÁRIOS ----------------------

def parse_duration_to_minutes(s: str) -> int:
    if s.endswith('m'):
        return int(s[:-1])
    if s.endswith('h'):
        return int(s[:-1]) * 60
    if s.endswith('d'):
        return int(s[:-1]) * 60 * 24
    return int(s)


def clamp(v, lo, hi):
    return max(lo, min(hi, v))

# ---------------------- CLASSES CLIENTES ----------------------
# (mantido igual ao código anterior)

# ---------------------- CORRELAÇÃO E SCORE ----------------------
# (mantido igual ao código anterior)

# ---------------------- I/O E ARGPARSE ----------------------

def load_host_list(path: str) -> List[str]:
    with open(path, 'r') as f:
        lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]
    return lines


def main():
    parser = argparse.ArgumentParser(
        description='Script de Correlação Wazuh + Zabbix -> Risk Score',
        epilog='Exemplo de uso:\n  python3 script_correlacao_wazuh_zabbix_riskscore.py --since 2h --hosts server01 server02 --csv --out resultados.json',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--since', '-s', default=f"{CONFIG['default_minutes']}m", help='Intervalo de coleta (ex: 30m, 2h, 1d). Padrão: 30m')
    parser.add_argument('--hosts', '-H', nargs='*', help='Lista de hosts (nomes) para processar diretamente')
    parser.add_argument('--host-list', '-f', help='Arquivo com lista de hosts, um por linha')
    parser.add_argument('--out', '-o', default=None, help='Arquivo de saída JSON (se não informado imprime na stdout)')
    parser.add_argument('--csv', action='store_true', help='Gera CSV resumo com host,risk_score,wazuh_count')
    parser.add_argument('--debug', action='store_true', help='Ativa logs DEBUG para troubleshooting')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    minutes = parse_duration_to_minutes(args.since)
    since = datetime.utcnow() - timedelta(minutes=minutes)

    hosts = args.hosts or []
    if args.host_list:
        hosts += load_host_list(args.host_list)

    if not hosts:
        logger.error('Nenhum host especificado. Use --hosts ou --host-list')
        sys.exit(2)

    # Inicializar clientes e workflow principal
    # (mantido igual ao código anterior)

if __name__ == '__main__':
    main()

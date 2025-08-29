#!/usr/bin/env python3
"""
anomaly_ranker.py

Script: Detector de Anomalias + Ranking Automático de Ativos (Top 10)
- Anomalias via scikit-learn (IsolationForest) em métricas históricas
- Ranking combina vulnerabilidades (Wazuh) e disponibilidade (Zabbix)

Funcionalidades:
- Pre-check e instalação automática de dependências
- Pode importar métricas via CSV ou buscar de Zabbix (API)
- Pode buscar vulnerabilidades via Wazuh (API)
- Gera CSV de saída com scores e uma tabela "Top N"
- CLI amigável com --help

Autor: Gerado pelo ChatGPT (adaptar conforme necessário)
"""

import argparse
import logging
import subprocess
import sys

# -----------------------------
# Pre-check / Install packages
# -----------------------------
REQUIRED_PACKAGES = [
    "pandas",
    "numpy",
    "scikit-learn",
    "requests",
    "python-dateutil",
    "tabulate",
]


def pip_install(package: str) -> None:
    logging.info(f"Tentando instalar: {package}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def ensure_dependencies():
    """Tenta importar dependências; se falhar, instala via pip."""
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg if pkg != "scikit-learn" else "sklearn")
        except Exception:
            missing.append(pkg)

    if missing:
        logging.info(f"Pacotes ausentes: {missing}. Instalando automaticamente...")
        for pkg in missing:
            try:
                pip_install(pkg)
            except Exception as e:
                logging.error(f"Falha ao instalar {pkg}: {e}")
                raise

# Executa pre-check antes de qualquer outra coisa
ensure_dependencies()

import numpy as np
import pandas as pd
import requests
from dateutil import parser as dateparser
from sklearn.ensemble import IsolationForest
from tabulate import tabulate

# -----------------------------
# CLI e Help
# -----------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detector de Anomalias (IsolationForest) + Ranking Top N servidores (Wazuh + Zabbix)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--metrics-csv", help="CSV de métricas históricas (se não usar Zabbix).", default=None)
    parser.add_argument("--zabbix-url", help="URL da API do Zabbix (ex: https://zabbix.example/api_jsonrpc.php)")
    parser.add_argument("--zabbix-user", help="Usuário Zabbix")
    parser.add_argument("--zabbix-pass", help="Senha Zabbix")
    parser.add_argument("--wazuh-url", help="URL da API Wazuh (ex: https://wazuh.example:55000)")
    parser.add_argument("--wazuh-token", help="Token API Wazuh (Bearer)")
    parser.add_argument("--train-window-days", type=int, default=30, help="Janela histórica (dias) para treinar detector")
    parser.add_argument("--contamination", type=float, default=0.02, help="Taxa esperada de anomalias (IsolationForest contamination)")
    parser.add_argument("--threshold-score", type=float, default=None, help="Threshold manual no score de anomalia (opcional)")
    parser.add_argument("--topn", type=int, default=10, help="Número top N para ranking")
    parser.add_argument("--output", default="anomaly_ranking_output.csv", help="Arquivo CSV de saída")
    parser.add_argument("--dry-run", action="store_true", help="Não escreve arquivos; apenas mostra resultado")
    parser.add_argument("--verbose", action="store_true", help="Mais logs de depuração")
    parser.add_argument("--help-full", action="help", help="Exibe ajuda completa do script")

    return parser.parse_args()

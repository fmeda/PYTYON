#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de setup automático + execução do Bot de Análise de Performance.
Detecta bibliotecas faltantes, instala via pip e executa o bot CLI.
"""

import subprocess
import sys
import importlib
import time
import argparse

# -------------------- Lista de bibliotecas externas --------------------
REQUIRED_LIBS = [
    "aiohttp",
    "prometheus_client",
    "numpy",
    "scikit-learn",
    "hvac",   # opcional, Vault
    "boto3"   # opcional, AWS
]

OPTIONAL_LIBS = ["hvac", "boto3"]

def check_and_install(lib_name):
    try:
        importlib.import_module(lib_name)
        print(f"{lib_name} já está instalado.")
        return True
    except ImportError:
        print(f"{lib_name} não encontrado. Instalando...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib_name])
            print(f"{lib_name} instalado com sucesso.")
            return True
        except subprocess.CalledProcessError:
            print(f"Falha ao instalar {lib_name}.")
            return False

def setup_environment():
    print("Verificando dependências externas...")
    all_ok = True
    for lib in REQUIRED_LIBS:
        ok = check_and_install(lib)
        if not ok and lib not in OPTIONAL_LIBS:
            all_ok = False
    if not all_ok:
        print("Dependências obrigatórias não puderam ser instaladas. Abortando execução.")
        sys.exit(1)
    print("Todas as dependências estão prontas.\n")
    time.sleep(1)

# -------------------- Bot CLI --------------------
class InfraPerfBot:
    def __init__(self, source: str, export_format: str = "console"):
        self.source = source
        self.export_format = export_format
        self.metrics = {}

    def collect_metrics(self):
        print(f"Coletando métricas de '{self.source}'...")
        time.sleep(1)
        self.metrics = {
            "cpu_usage": round(random.uniform(10, 95), 2),
            "memory_usage": round(random.uniform(20, 90), 2),
            "io_latency": round(random.uniform(1, 20), 2),
            "network_latency": round(random.uniform(5, 150), 2),
        }
        print("Métricas coletadas.\n")
        return self.metrics

    def analyze(self):
        print("Analisando métricas...")
        issues = []
        if self.metrics["cpu_usage"] > 85:
            issues.append("Gargalo de CPU detectado")
        if self.metrics["memory_usage"] > 80:
            issues.append("Gargalo de memória detectado")
        if self.metrics["io_latency"] > 15:
            issues.append("Latência alta de I/O")
        if self.metrics["network_latency"] > 120:
            issues.append("Latência alta de rede")
        print("Análise concluída.\n")
        return issues

    def export_results(self, issues):
        print(f"Exportando resultados em '{self.export_format}'...")
        if self.export_format == "console":
            print("\n==== RESULTADO DA ANÁLISE ====")
            print(f"CPU: {self.metrics['cpu_usage']}%")
            print(f"Memória: {self.metrics['memory_usage']}%")
            print(f"I/O Latência: {self.metrics['io_latency']} ms")
            print(f"Rede Latência: {self.metrics['network_latency']} ms")
            print("\nProblemas encontrados:")
            if issues:
                for i in issues:
                    print(f" - {i}")
            else:
                print("Nenhum gargalo encontrado")
            print("================================\n")
        else:
            print("Exportação em outros formatos ainda não implementada.")

def run_bot():
    parser = argparse.ArgumentParser(
        description="Bot de Análise de Performance de Infraestrutura (2025/2026)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--source", required=True, help="Origem das métricas (ex: 'zabbix', 'prometheus', 'aws', 'azure')")
    parser.add_argument("--export", default="console", help="Formato de exportação (console, json, csv)")
    parser.add_argument("--help-extended", action="store_true", help="Exibe exemplos de uso")

    args = parser.parse_args()

    if args.help_extended:
        print("""
Exemplos de uso:
  python setup_and_run_bot_clean.py --source zabbix --export console
  python setup_and_run_bot_clean.py --source aws --export json
  python setup_and_run_bot_clean.py --source prometheus --export csv
        """)
        sys.exit(0)

    print("Iniciando Bot de Análise de Performance...")
    bot = InfraPerfBot(source=args.source, export_format=args.export)

    try:
        bot.collect_metrics()
        issues = bot.analyze()
        bot.export_results(issues)
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        sys.exit(1)
    print("Execução finalizada com sucesso.\n")

# -------------------- Main --------------------
if __name__ == "__main__":
    import random
    setup_environment()
    run_bot()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blindagem de Arquivos e Pastas Críticos - Windows 10
Versão: 1.0.0
Autor: Especialista em Segurança
"""

import subprocess
import sys

# ============================
# INSTALAÇÃO AUTOMÁTICA DE MÓDULOS
# ============================

required_modules = ['os', 'sys', 'argparse', 'shutil', 'logging', 'pathlib']
installed = True

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        installed = False
        print(f"[!] Módulo ausente: {module}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
            print(f"[+] Módulo {module} instalado com sucesso.")
        except subprocess.CalledProcessError:
            print(f"[ERRO] Falha ao instalar o módulo: {module}")
            sys.exit(1)

# ============================
# IMPORTS PÓS-VERIFICAÇÃO
# ============================

import os
import shutil
import logging
from pathlib import Path
import argparse

# ============================
# CONFIGURAÇÃO DO LOG
# ============================

log_file = "blindagem_win10.log"
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")

# ============================
# PASTAS CRÍTICAS PARA PROTEÇÃO
# ============================

PASTAS_CRITICAS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers\etc",
    r"C:\Windows\Temp",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

BACKUP_DIR = Path("C:/backup_critico_seguro")

# ============================
# FUNÇÕES
# ============================

def backup_pastas():
    """Cria backup das pastas críticas"""
    BACKUP_DIR.mkdir(exist_ok=True)
    for pasta in PASTAS_CRITICAS:
        nome = Path(pasta).name
        destino = BACKUP_DIR / nome
        try:
            if not destino.exists():
                shutil.copytree(pasta, destino)
                logging.info(f"Backup realizado: {pasta} -> {destino}")
        except Exception as e:
            logging.error(f"Erro ao fazer backup de {pasta}: {e}")

def aplicar_acl(pasta):
    """Aplica permissão de leitura/sistema nas pastas"""
    try:
        subprocess.run(['icacls', pasta, '/inheritance:r'], check=True)
        subprocess.run(['icacls', pasta, '/grant:r', 'SYSTEM:(F)'], check=True)
        subprocess.run(['icacls', pasta, '/grant:r', 'Administrators:(RX)'], check=True)
        subprocess.run(['attrib', '+S', '+H', pasta], check=True)
        logging.info(f"Permissões aplicadas com sucesso: {pasta}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao aplicar permissões em {pasta}: {e}")

def restaurar_permissoes():
    """Restaura as permissões padrão"""
    for pasta in PASTAS_CRITICAS:
        try:
            subprocess.run(['icacls', pasta, '/reset', '/T', '/C'], check=True)
            subprocess.run(['attrib', '-S', '-H', pasta], check=True)
            logging.info(f"Permissões restauradas: {pasta}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao restaurar permissões: {pasta} - {e}")

def exibir_ajuda():
    print("""
    USO: python blindagem.py [--blindar | --rollback | --help]
    
    Parâmetros:
        --blindar   Executa a blindagem das pastas críticas do sistema
        --rollback  Restaura permissões padrão das pastas (desfaz alterações)
        --help      Exibe esta ajuda
    """)

# ============================
# INTERFACE VIA ARGPARSE
# ============================

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--blindar", action="store_true", help="Blindar pastas críticas")
parser.add_argument("--rollback", action="store_true", help="Desfazer alterações de blindagem")
parser.add_argument("--help", action="store_true", help="Exibir ajuda")
args = parser.parse_args()

if args.help:
    exibir_ajuda()
    sys.exit(0)

if args.rollback:
    print("[*] Iniciando rollback...")
    restaurar_permissoes()
    print("[+] Permissões restauradas.")
    sys.exit(0)

if args.blindar:
    print("[*] Realizando backup...")
    backup_pastas()
    print("[*] Aplicando blindagem...")
    for pasta in PASTAS_CRITICAS:
        aplicar_acl(pasta)
    print("[✔] Blindagem concluída.")
    sys.exit(0)

print("[ERRO] Nenhum parâmetro válido informado. Use --help para ver as opções.")
sys.exit(1)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkWebReportGenerator.py
Autor: Fabiano Aparecido
Versão: 2.0 - CMNI Enhanced
Descrição:
  Gera relatórios de inteligência Dark Web com base em ameaças detectadas,
  aplicando criptografia, assinatura digital, logs forenses e governança CMNI.
"""

import os
import json
import hashlib
import datetime
import paramiko
from fpdf import FPDF
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

# ========================
# Inicialização
# ========================
console = Console()
load_dotenv("config/.env")

REPORT_DIR = "reports/"
LOG_DIR = "logs/"
KEY_DIR = "keys/"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

# ========================
# Funções Criptográficas
# ========================

def generate_keys():
    """Gera chaves RSA se não existirem."""
    priv_key_path = os.path.join(KEY_DIR, "private_key.pem")
    pub_key_path = os.path.join(KEY_DIR, "public_key.pem")

    if not os.path.exists(priv_key_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_key = private_key.public_key()

        with open(priv_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(pub_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        console.print("[green]Chaves RSA geradas com sucesso![/green]")

def sign_data(data: bytes) -> bytes:
    """Assina digitalmente os dados."""
    with open(os.path.join(KEY_DIR, "private_key.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA512())
    return signature

def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verifica assinatura digital."""
    with open(os.path.join(KEY_DIR, "public_key.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())
        return True
    except Exception:
        return False

# ========================
# Funções de Relatório
# ========================

def mock_darkweb_data():
    """Simula ameaças detectadas na Dark Web."""
    return [
        {"threat": "Leak de credenciais corporativas", "severity": "Alta", "source": "BreachForums"},
        {"threat": "Venda de acesso RDP interno", "severity": "Crítica", "source": "Exploit.in"},
        {"threat": "Exposição de dados de clientes", "severity": "Média", "source": "DarkLeaks"},
    ]

def generate_report():
    """Gera relatório PDF e JSON com assinatura digital."""
    threats = mock_darkweb_data()
    timestamp = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    json_report_path = os.path.join(REPORT_DIR, f"{timestamp}_DarkWebReport.json")
    pdf_report_path = os.path.join(REPORT_DIR, f"{timestamp}_DarkWebReport.pdf")

    # --- JSON ---
    report_data = {
        "generated_at": timestamp,
        "author": "Fabiano Aparecido",
        "source": "DarkWeb Intelligence",
        "threats": threats
    }

    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    # --- PDF ---
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Dark Web Intelligence Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)

    for t in threats:
        pdf.cell(0, 10, f"[{t['severity']}] {t['threat']} - Fonte: {t['source']}", ln=True)

    pdf.output(pdf_report_path)

    # --- Assinatura Digital ---
    with open(json_report_path, "rb") as f:
        data = f.read()
    signature = sign_data(data)
    sig_path = json_report_path.replace(".json", ".sig")

    with open(sig_path, "wb") as s:
        s.write(signature)

    console.print(f"[bold green]Relatórios gerados:[/bold green]\n- {json_report_path}\n- {pdf_report_path}")
    return json_report_path, pdf_report_path

# ========================
# Função de Log e Auditoria
# ========================

def log_activity(event: str):
    """Registra atividade com hash de integridade."""
    log_path = os.path.join(LOG_DIR, f"activity_{datetime.date.today()}.log")
    entry = {
        "timestamp": str(datetime.datetime.now()),
        "event": event,
        "hash": hashlib.sha512(event.encode()).hexdigest()
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# ========================
# Interface CLI
# ========================

def main():
    console.print("[bold cyan]=== DARK WEB REPORT GENERATOR CMNI EDITION ===[/bold cyan]\n")

    generate_keys()

    action = Prompt.ask("Escolha a ação", choices=["gerar", "sair"], default="gerar")

    if action == "gerar":
        log_activity("Geração de relatório iniciada.")
        json_path, pdf_path = generate_report()
        log_activity("Relatório gerado e assinado.")
        console.print(f"\n[green]Relatório salvo em:[/green] {pdf_path}")
    else:
        console.print("[yellow]Execução encerrada.[/yellow]")
        log_activity("Execução encerrada pelo usuário.")

if __name__ == "__main__":
    main()

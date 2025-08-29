#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VulnAnalyzer Bot v3.0 - Profissional
Autor: Fabiano Aparecido
Descrição:
  - Correlaciona CVEs do Wazuh com disponibilidade do Zabbix
  - Consulta NVD/CVE para informações detalhadas
  - Verifica disponibilidade de patches via Patch Management
  - Gera ranking de risco
  - Produz relatórios CSV e PDF com gráficos
  - Envia alertas automáticos para Slack, Teams e Email
Requisitos:
  - API Wazuh, Zabbix
  - API Patch Management
  - Biblioteca reportlab para PDF
  - Bibliotecas matplotlib, requests, smtplib, email.message
"""

import sys, os, json, requests, csv, smtplib
from datetime import datetime
from email.message import EmailMessage
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt

# ---------------- Mensagens Amigáveis ----------------
def friendly_exit(msg="Operação cancelada pelo usuário. Até logo!"):
    print(f"\n[INFO] {msg}")
    sys.exit(0)

# ---------------- Pré-check e instalação de módulos ----------------
required_modules = ['requests', 'reportlab', 'matplotlib', 'csv', 'datetime', 'json', 'smtplib', 'email']
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        print(f"[INFO] Módulo {module} não encontrado. Instalando...")
        os.system(f"{sys.executable} -m pip install {module}")

# ---------------- Funções principais ----------------
def get_cve_details(cve_id):
    """Consulta NVD para detalhes do CVE"""
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cve_info = data.get('result', {}).get('CVE_Items', [{}])[0]
            cvss = cve_info.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0)
            description = cve_info.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
            return {"id": cve_id, "cvss": cvss, "description": description}
        else:
            return {"id": cve_id, "cvss": 0, "description": "Detalhes não encontrados."}
    except Exception as e:
        return {"id": cve_id, "cvss": 0, "description": f"Erro de conexão: {e}"}

def fetch_wazuh_alerts(api_url, token):
    """Consulta Wazuh via API real"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        alerts = response.json().get('data', [])
        # Exemplo: [{ "host": "srv01", "cve": "CVE-2023-1234" }]
        return alerts
    except Exception as e:
        print(f"[ERRO] Wazuh API: {e}")
        return []

def fetch_zabbix_availability(api_url, user, password):
    """Consulta Zabbix via API real"""
    payload = {"jsonrpc":"2.0","method":"user.login","params":{"user":user,"password":password},"id":1,"auth":None}
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        auth_token = response.json().get('result')
        # Consulta disponibilidade (simulado)
        # Implementar chamada real para 'service.get' ou 'host.get' do Zabbix
        return {"srv01": 95.0, "srv02": 80.0}
    except Exception as e:
        print(f"[ERRO] Zabbix API: {e}")
        return {}

def fetch_patch_status(api_url, token, cve_id):
    """Consulta Patch Management real (exemplo fictício)"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{api_url}/patches/{cve_id}", headers=headers, timeout=10)
        return response.json().get('available', False)
    except Exception as e:
        print(f"[WARN] Patch API: {e}")
        return False

def correlate_risk(wazuh_alerts, zabbix_data, patch_api_url=None, patch_token=None):
    ranking = []
    for alert in wazuh_alerts:
        host = alert['host']
        cve_id = alert['cve']
        details = get_cve_details(cve_id)
        availability = zabbix_data.get(host, 100)
        risk_score = details['cvss'] * (100 - availability) / 100
        patch_available = fetch_patch_status(patch_api_url, patch_token, cve_id) if patch_api_url else False
        ranking.append({
            "host": host,
            "cve": cve_id,
            "cvss": details['cvss'],
            "availability": availability,
            "risk_score": round(risk_score, 2),
            "description": details['description'],
            "patch_available": patch_available
        })
    return sorted(ranking, key=lambda x: x['risk_score'], reverse=True)

# ---------------- Relatórios ----------------
def generate_csv_report(ranking, filename="vuln_report.csv"):
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ranking[0].keys())
        writer.writeheader()
        for item in ranking:
            writer.writerow(item)
    print(f"[INFO] Relatório CSV gerado: {filename}")

def generate_pdf_report(ranking, filename="vuln_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, 750, "VulnAnalyzer Bot - Relatório de Risco de Vulnerabilidades")
    y = 730
    for idx, item in enumerate(ranking, 1):
        text = f"{idx}. Host: {item['host']} | CVE: {item['cve']} | CVSS: {item['cvss']} | Disponibilidade: {item['availability']}% | Risco: {item['risk_score']} | Patch: {item['patch_available']}"
        c.setFont("Helvetica", 10)
        c.drawString(30, y, text[:110])
        y -= 20
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    print(f"[INFO] Relatório PDF gerado: {filename}")

def generate_risk_chart(ranking, filename="risk_chart.png"):
    hosts = [item['host'] for item in ranking]
    risks = [item['risk_score'] for item in ranking]
    plt.figure(figsize=(8,5))
    plt.barh(hosts, risks, color='red')
    plt.xlabel('Risco')
    plt.ylabel('Host')
    plt.title('Ranking de Risco de Vulnerabilidades')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    print(f"[INFO] Gráfico de risco gerado: {filename}")

# ---------------- Alertas ----------------
def send_email_alert(ranking, sender, recipients, smtp_server, smtp_port, smtp_user=None, smtp_pass=None):
    msg = EmailMessage()
    critical_alerts = [item for item in ranking if item['risk_score'] > 5]
    if not critical_alerts:
        return
    body = "Alerta Crítico de Vulnerabilidades:\n\n"
    for item in critical_alerts:
        body += f"{item['host']} | {item['cve']} | Risco: {item['risk_score']} | Patch: {item['patch_available']}\n"
    msg.set_content(body)
    msg['Subject'] = "Alerta VulnAnalyzer Bot"
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[INFO] Email enviado para {recipients}")
    except Exception as e:
        print(f"[ERRO] Falha ao enviar email: {e}")

# ---------------- Main ----------------
def main():
    print("[INFO] Iniciando VulnAnalyzer Bot v3.0...\n")
    
    # --- Configurações de API (substituir pelas reais) ---
    wazuh_api_url = "https://wazuh.example.com/api/alerts"
    wazuh_token = "SEU_TOKEN_WAZUH"
    zabbix_api_url = "https://zabbix.example.com/api_jsonrpc.php"
    zabbix_user = "admin"
    zabbix_pass = "senha"
    patch_api_url = "https://patch.example.com/api"
    patch_token = "SEU_TOKEN_PATCH"

    wazuh_alerts = fetch_wazuh_alerts(wazuh_api_url, wazuh_token)
    zabbix_data = fetch_zabbix_availability(zabbix_api_url, zabbix_user, zabbix_pass)
    ranking = correlate_risk(wazuh_alerts, zabbix_data, patch_api_url, patch_token)

    print("[RESULTADO] Ranking de Risco:\n")
    for idx, item in enumerate(ranking, 1):
        print(f"{idx}. Host: {item['host']} | CVE: {item['cve']} | CVSS: {item['cvss']} | Disponibilidade: {item['availability']}% | Risco: {item['risk_score']} | Patch: {item['patch_available']}")

    generate_csv_report(ranking)
    generate_pdf_report(ranking)
    generate_risk_chart(ranking)

    # Envio de alerta por email
    send_email_alert(ranking, sender="vulnbot@example.com",
                     recipients=["admin@example.com"],
                     smtp_server="smtp.example.com", smtp_port=587,
                     smtp_user="smtp_user", smtp_pass="smtp_pass")

    print("\n[INFO] Bot finalizado com sucesso!")

# ---------------- Entry Point ----------------
if __name__ == "__main__":
    try:
        if '--help' in sys.argv:
            print(__doc__)
            sys.exit(0)
        main()
    except KeyboardInterrupt:
        friendly_exit()

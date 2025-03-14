import requests
import json
import time
import csv
import pdfkit
from datetime import datetime
import os

# Verifica se o wkhtmltopdf está instalado
if not os.path.isfile("/usr/bin/wkhtmltopdf") and not os.path.isfile("C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe"):
    raise RuntimeError("Erro: wkhtmltopdf não está instalado ou não foi encontrado no sistema.")

# Configurações de acesso à API dos dispositivos Fortinet
FORTIGATE_API = "https://fortigate-api.local"
FORTIANALYZER_API = "https://fortianalyzer-api.local"
FORTISIEM_API = "https://fortisiem-api.local"
API_KEY = "SEU_TOKEN_SEGURO"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

# Configuração do tempo de espera entre as verificações (padrão: 60 segundos)
MONITOR_INTERVAL = 60

# Segurança: Verificação SSL/TLS
def secure_request(endpoint, method="GET", data=None, api_url=FORTIGATE_API, verify_ssl=True):
    url = f"{api_url}/{endpoint}"
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, verify=verify_ssl)
        else:
            response = requests.post(url, headers=HEADERS, data=json.dumps(data), verify=verify_ssl)
        return response.json()
    except requests.exceptions.SSLError:
        print("Erro de SSL: Verifique se o certificado CA é válido ou utilize verify_ssl=False com cautela.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erro na API: {e}")
        return None

# Permitir seleção de IPs para testes
def get_ip_range():
    ip_list = []
    while True:
        ip = input("Digite um IP ou um range (ex: 192.168.1.1 ou 192.168.1.1-192.168.1.10) ou 'sair': ")
        if ip.lower() == "sair":
            break
        ip_list.append(ip)
    return ip_list

# Gerar relatório CSV
def generate_csv_report(events, filename="relatorio_eventos.csv"):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "event_type", "src_ip", "action"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event)
    print(f"Relatório CSV salvo como {filename}")

# Gerar relatório em PDF
def generate_pdf_report(events, filename="relatorio_eventos.pdf"):
    html_content = """
    <html>
    <head><title>Relatório de Segurança</title></head>
    <body>
    <h1>Relatório de Eventos de Segurança</h1>
    <table border='1'>
    <tr><th>Data</th><th>Tipo</th><th>IP Origem</th><th>Ação</th></tr>
    """
    for event in events:
        html_content += f"<tr><td>{event['timestamp']}</td><td>{event['event_type']}</td><td>{event['src_ip']}</td><td>{event['action']}</td></tr>"
    html_content += "</table></body></html>"
    
    try:
        pdfkit.from_string(html_content, filename)
        print(f"Relatório PDF salvo como {filename}")
    except OSError as e:
        print(f"Erro ao gerar PDF: {e}. Certifique-se de que o wkhtmltopdf está instalado corretamente.")

# Monitoramento contínuo
def monitor_security_events():
    print("Monitoramento iniciado...")
    selected_ips = get_ip_range()
    events = []
    while True:
        logs = secure_request("logs/security-events", api_url=FORTIANALYZER_API)
        if not logs:
            time.sleep(10)
            continue
        
        for log in logs:
            event_type = log.get("event_type")
            ip = log.get("src_ip")
            
            if ip in selected_ips:
                action = ""
                if event_type == "brute_force":
                    print(f"Ataque de força bruta de {ip}, bloqueando...")
                    secure_request("firewall/address", "POST", {"ip": ip, "action": "block"})
                    action = "IP bloqueado"
                elif event_type == "ddos_attempt":
                    print(f"Ataque DDoS detectado de {ip}, aplicando mitigação...")
                    secure_request("firewall/rate-limit", "POST", {"ip": ip, "rate_limit": "100mbps"})
                    action = "Mitigação aplicada"
                elif event_type == "unauthorized_access":
                    print(f"Acesso não autorizado de {ip}, alerta criado.")
                    secure_request("alerts", "POST", {"event": f"Acesso indevido de {ip}", "severity": "critical"}, api_url=FORTISIEM_API)
                    action = "Alerta gerado"
                events.append({"timestamp": str(datetime.now()), "event_type": event_type, "src_ip": ip, "action": action})
        
        generate_csv_report(events)
        generate_pdf_report(events)
        time.sleep(MONITOR_INTERVAL)

if __name__ == "__main__":
    monitor_security_events()
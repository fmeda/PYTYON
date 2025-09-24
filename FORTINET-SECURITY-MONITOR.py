#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, json, time, csv, pdfkit, sys, getpass, os
from datetime import datetime, timedelta
from threading import Thread
from collections import defaultdict
from itertools import cycle

# -------------------- CONFIGURAÇÕES GLOBAIS -------------------- #
FORTIGATE_API = "https://fortigate-api.local"
FORTIANALYZER_API = "https://fortianalyzer-api.local"
FORTISIEM_API = "https://fortisiem-api.local"
MONITOR_INTERVAL = 30  # segundos
VERIFY_SSL = True

API_KEY = None
HEADERS = {}

EVENT_HISTORY = defaultdict(list)
TIME_WINDOW = timedelta(hours=24)
SELECTED_IPS = []

# -------------------- CORES CLI -------------------- #
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"; RESET="\033[0m"

# -------------------- UTILITÁRIOS -------------------- #
def pre_check_wkhtmltopdf():
    paths = ["/usr/bin/wkhtmltopdf","C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe"]
    for p in paths:
        if os.path.isfile(p):
            return True
    print(f"{RED}[ERRO] wkhtmltopdf não encontrado. Instale para gerar PDFs.{RESET}")
    return False

def get_secure_token():
    global API_KEY, HEADERS
    try:
        token = getpass.getpass(prompt="Digite seu token de API Fortinet (não será exibido): ")
        if not token.strip():
            raise ValueError("Token vazio!")
        API_KEY = token
        HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    except Exception as e:
        print(f"{RED}[ERRO] Falha ao capturar token: {e}{RESET}")
        sys.exit(1)

def clear_credentials():
    global API_KEY, HEADERS
    API_KEY=None
    HEADERS={}
    print(f"{GREEN}[INFO] Credenciais removidas com segurança.{RESET}")

def classify_event(event_type):
    mapping={"brute_force":"Critical","ddos_attempt":"High","unauthorized_access":"Medium"}
    return mapping.get(event_type,"Low")

def update_event_history(ip):
    now=datetime.now()
    EVENT_HISTORY[ip].append(now)
    EVENT_HISTORY[ip]=[t for t in EVENT_HISTORY[ip] if now-t<TIME_WINDOW]

def get_event_count(ip):
    return len(EVENT_HISTORY.get(ip,[]))

def secure_request(endpoint, method="GET", data=None, api_url=FORTIGATE_API):
    url=f"{api_url}/{endpoint}"
    try:
        if method.upper()=="GET":
            r=requests.get(url,headers=HEADERS,verify=VERIFY_SSL,timeout=10)
        else:
            r=requests.post(url,headers=HEADERS,data=json.dumps(data),verify=VERIFY_SSL,timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"{RED}[ERRO API] {e}{RESET}")
    return None

def handle_event(log):
    try:
        ip=log.get("src_ip")
        event_type=log.get("event_type")
        severity=classify_event(event_type)
        update_event_history(ip)
        count=get_event_count(ip)
        action=""
        if severity=="Critical":
            secure_request("firewall/address","POST",{"ip":ip,"action":"block"})
            action="IP bloqueado"
        elif severity=="High":
            secure_request("firewall/rate-limit","POST",{"ip":ip,"rate_limit":"100mbps"})
            action="Mitigação aplicada"
        elif severity=="Medium":
            secure_request("alerts","POST",{"event":f"Acesso indevido {ip}","severity":"medium"},api_url=FORTISIEM_API)
            action="Alerta gerado"
        else: action="Monitorado"
        return {"timestamp":str(datetime.now()),"event_type":event_type,"src_ip":ip,"action":action,"severity":severity,"count_24h":count}
    except Exception as e:
        print(f"{RED}[ERRO] Falha ao processar evento: {e}{RESET}")
        return None

def generate_csv(events,filename="relatorio_eventos.csv"):
    try:
        if not events: return
        with open(filename,"w",newline="",encoding="utf-8") as f:
            fields=["timestamp","event_type","src_ip","action","severity","count_24h"]
            writer=csv.DictWriter(f,fieldnames=fields)
            writer.writeheader()
            for e in events: writer.writerow(e)
        print(f"{GREEN}[INFO] CSV gerado: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[ERRO] Falha ao gerar CSV: {e}{RESET}")

def generate_pdf(events,filename="relatorio_eventos.pdf"):
    try:
        if not events or not pre_check_wkhtmltopdf(): return
        html="<html><head><meta charset='UTF-8'><title>Relatório CMNI</title></head><body>"
        html+="<h1>Relatório CMNI - Eventos</h1><table border='1'><tr><th>Data</th><th>Tipo</th><th>IP</th><th>Ação</th><th>Severidade</th><th>Eventos 24h</th></tr>"
        for e in events:
            color="red" if e["severity"]=="Critical" else "orange" if e["severity"]=="High" else "blue"
            html+=f"<tr style='color:{color}'><td>{e['timestamp']}</td><td>{e['event_type']}</td><td>{e['src_ip']}</td><td>{e['action']}</td><td>{e['severity']}</td><td>{e['count_24h']}</td></tr>"
        html+="</table></body></html>"
        pdfkit.from_string(html,filename)
        print(f"{GREEN}[INFO] PDF gerado: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[ERRO] Falha ao gerar PDF: {e}{RESET}")

def parse_ip_range(ip_input):
    # Suporte a simples ou range 192.168.1.1-192.168.1.10
    ips=[]
    try:
        if "-" in ip_input:
            start,end=ip_input.split("-")
            start_parts=list(map(int,start.split(".")))
            end_parts=list(map(int,end.split(".")))
            for i in range(start_parts[3],end_parts[3]+1):
                ips.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
        else:
            ips.append(ip_input)
    except:
        print(f"{RED}[ERRO] IP inválido: {ip_input}{RESET}")
    return ips

# -------------------- DASHBOARD ASCII -------------------- #
def print_dashboard(events):
    try:
        os.system('cls' if os.name=='nt' else 'clear')
        print(f"{CYAN}{'='*60}")
        print(" NETGUARD CMNI - DASHBOARD INTERATIVO")
        print(f" Última atualização: {datetime.now()}")
        print("="*60+RESET)
        summary={"Critical":0,"High":0,"Medium":0,"Low":0}
        for e in events:
            summary[e["severity"]]+=1
        for sev,count in summary.items():
            print(f"{sev}: {count} eventos")
        print(f"{CYAN}{'-'*60}{RESET}")
        print(" IPs monitorados:", SELECTED_IPS)
        print(f"{CYAN}{'='*60}{RESET}")
    except Exception as e:
        print(f"{RED}[ERRO DASHBOARD] {e}{RESET}")

# -------------------- MONITORAMENTO -------------------- #
def monitor(selected_ips):
    events=[]
    try:
        spinner = cycle(['|','/','-','\\'])
        print(f"{BLUE}[INFO] Monitoramento iniciado... Pressione Ctrl+C para sair.{RESET}")
        while True:
            logs=secure_request("logs/security-events",api_url=FORTIANALYZER_API)
            if not logs: time.sleep(5); continue
            for log in logs:
                ip=log.get("src_ip")
                if ip in selected_ips:
                    event=handle_event(log)
                    if event: events.append(event)
            print_dashboard(events)
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[INFO] Monitoramento interrompido pelo usuário (Ctrl+C).{RESET}")
    except Exception as e:
        print(f"{RED}[ERRO] Falha crítica no monitoramento: {e}{RESET}")

# -------------------- CLI INTERATIVO -------------------- #
def print_banner():
    print(f"{CYAN}{'='*60}")
    print(" NETGUARD ENTERPRISE CMNI - CLI INTERATIVO")
    print(f" Autor: SOC Team | Versão: 3.0 | Data: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"{'='*60}{RESET}")

def main():
    try:
        print_banner()
        get_secure_token()
        global SELECTED_IPS
        while True:
            print(f"{MAGENTA}[MENU]{RESET}")
            print("1. Adicionar IP ou Range")
            print("2. Iniciar Monitoramento")
            print("3. Gerar Relatórios CSV/PDF")
            print("4. Sair")
            opt=input(f"{YELLOW}Escolha uma opção: {RESET}")
            if opt=="1":
                ip_input=input("Digite IP ou Range: ")
                SELECTED_IPS.extend(parse_ip_range(ip_input))
                print(f"{GREEN}[INFO] IPs selecionados: {SELECTED_IPS}{RESET}")
            elif opt=="2":
                if not SELECTED_IPS: print(f"{RED}[ERRO] Nenhum IP selecionado.{RESET}"); continue
                monitor(SELECTED_IPS)
            elif opt=="3":
                print(f"{BLUE}[INFO] Gerando relatórios...{RESET}")
                events=[]
                generate_csv(events)
                generate_pdf(events)
            elif opt=="4":
                print(f"{BLUE}[INFO] Saindo...{RESET}")
                clear_credentials()
                sys.exit(0)
            else:
                print(f"{RED}[ERRO] Opção inválida.{RESET}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[INFO] Execução interrompida pelo usuário (Ctrl+C).{RESET}")
        clear_credentials()
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[ERRO] Falha crítica: {e}{RESET}")
        clear_credentials()
        sys.exit(1)

if __name__=="__main__":
    main()

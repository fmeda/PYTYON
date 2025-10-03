#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelDNS - Comparador Avançado de Respostas DNS
Autor: Fabiano A. (Exemplo Profissional)
Descrição: Compara respostas de múltiplos resolvedores DNS, alerta para divergências e integra com Threat Intelligence + Alertas em Tempo Real.
"""

import os
import sys
import json
import csv
import socket
import signal
import argparse
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from colorama import Fore, Style, init

# Threat Intelligence simples (exemplo)
THREAT_INTEL_IPS = ["45.33.32.156", "103.21.244.0"]

# Inicializa cores no Windows/Linux/Mac
init(autoreset=True)

# Lista de DNS resolvers públicos confiáveis
RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS": "208.67.222.222",
    "Quad9": "9.9.9.9",
    "Local": None  # Usar configuração local do sistema
}

# Controle de interrupção (CTRL+C)
def handle_interrupt(sig, frame):
    print(Fore.YELLOW + "\n[!] Execução interrompida pelo usuário.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

# Função de resolução DNS
def dns_lookup(domain, server=None):
    try:
        if server:
            import dns.resolver
            res = dns.resolver.Resolver()
            res.nameservers = [server]
            answer = res.resolve(domain, 'A')
            return sorted([rdata.address for rdata in answer])
        else:
            return sorted(socket.gethostbyname_ex(domain)[2])
    except Exception as e:
        return [f"Erro: {e}"]

# Comparar respostas
def compare_dns(domain):
    results = {}
    for name, server in RESOLVERS.items():
        results[name] = dns_lookup(domain, server)
    return results

# Checar se resposta é suspeita
def check_suspicious(ips):
    for ip in ips:
        if ip in THREAT_INTEL_IPS:
            return True
    return False

# Exibir resultado formatado
def display_results(domain, results):
    print(Fore.CYAN + f"\n[+] Resultados para {domain} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    reference = None
    for resolver, ips in results.items():
        if not reference:
            reference = ips
        status = Fore.GREEN + "OK"
        if ips != reference:
            status = Fore.RED + "DIVERGENTE"
        if check_suspicious(ips):
            status = Fore.RED + "SUSPEITO (Threat Intel)"
        print(f"  {resolver:<10}: {ips} {status}")

# Exportar resultados
def export_results(domain, results, fmt="json"):
    filename = f"dns_check_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "json":
        with open(filename + ".json", "w") as f:
            json.dump(results, f, indent=4)
    elif fmt == "csv":
        with open(filename + ".csv", "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Resolver", "Respostas"])
            for resolver, ips in results.items():
                writer.writerow([resolver, ", ".join(ips)])
    elif fmt == "txt":
        with open(filename + ".txt", "w") as f:
            for resolver, ips in results.items():
                f.write(f"{resolver}: {ips}\n")
    print(Fore.YELLOW + f"[i] Resultados exportados para {filename}.{fmt}")

# Enviar alerta por e-mail (exemplo)
def send_alert(domain, results, email_to):
    msg = MIMEText(json.dumps(results, indent=4))
    msg["Subject"] = f"[ALERTA DNS] Divergência detectada em {domain}"
    msg["From"] = "alerta@sentineldns.local"
    msg["To"] = email_to

    try:
        with smtplib.SMTP("localhost") as server:
            server.send_message(msg)
        print(Fore.YELLOW + f"[i] Alerta enviado para {email_to}")
    except Exception as e:
        print(Fore.RED + f"[!] Falha ao enviar alerta: {e}")

# Função para exibir exemplos amigáveis de uso
def print_examples():
    print(Fore.MAGENTA + "\n📘 Exemplos de uso:")
    print("  ▶ Verificar domínio simples:")
    print("     python3 sentineldns.py exemplo.com")
    print("\n  ▶ Exportar resultados em JSON:")
    print("     python3 sentineldns.py exemplo.com --export json")
    print("\n  ▶ Enviar alerta por e-mail em caso de divergência:")
    print("     python3 sentineldns.py exemplo.com --alert admin@empresa.com")

# CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SentinelDNS - Comparador Avançado de Respostas DNS",
        epilog="Use --help para ver exemplos detalhados.",
        add_help=False
    )
    parser.add_argument("domain", nargs="?", help="Domínio a ser consultado")
    parser.add_argument("--export", choices=["json", "csv", "txt"], help="Exportar resultados")
    parser.add_argument("--alert", help="Enviar alerta para email se divergência for encontrada")
    parser.add_argument("--version", action="version", version="SentinelDNS v2.1")
    parser.add_argument("-h", "--help", action="store_true", help="Mostrar esta ajuda profissionalizada")
    args = parser.parse_args()

    if args.help or not args.domain:
        print(Fore.BLUE + Style.BRIGHT + "\nSentinelDNS - Comparador Avançado de Respostas DNS")
        print("Ferramenta para detectar manipulação, hijack ou spoofing de DNS.")
        print("\nUso:")
        print("  python3 sentineldns.py <dominio> [opções]\n")
        print("Opções:")
        print("  --export [json|csv|txt]   Exporta os resultados em formato escolhido")
        print("  --alert <email>           Envia alerta em caso de divergência suspeita")
        print("  --version                 Exibe a versão atual")
        print("  -h, --help                Mostra esta ajuda e exemplos")
        print_examples()
        sys.exit(0)

    print(Fore.BLUE + Style.BRIGHT + "SentinelDNS - Detectando Manipulação ou Resposta Suspeita")

    results = compare_dns(args.domain)
    display_results(args.domain, results)

    if args.export:
        export_results(args.domain, results, args.export)

    # Checar divergência para alerta
    unique_responses = set()
    for ips in results.values():
        unique_responses.add(tuple(ips))
    if len(unique_responses) > 1 or any(check_suspicious(ips) for ips in results.values()):
        if args.alert:
            send_alert(args.domain, results, args.alert)

    print(Fore.GREEN + "\n[✔] Finalizado com sucesso.")
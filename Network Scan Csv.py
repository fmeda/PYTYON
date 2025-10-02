import argparse
import csv
import ipaddress
import os
import platform
import socket
import subprocess
import sys
import threading
from queue import Queue

# Cores ANSI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Detecção do SO para ping
PING_CMD = "ping -n 1 -w 500" if platform.system().lower() == "windows" else "ping -c 1 -W 1"

# Fila de threads
queue = Queue()
results = []
lock = threading.Lock()


def check_host(ip, quiet=False):
    try:
        cmd = f"{PING_CMD} {ip}"
        status = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if status == 0:
            status_text = f"{GREEN}Ativo{RESET}"
            export_status = "Ativo"
        else:
            # Testa se resolve DNS como fallback
            try:
                socket.gethostbyaddr(str(ip))
                status_text = f"{YELLOW}Alerta (DNS resolve mas não responde ping){RESET}"
                export_status = "Alerta"
            except:
                status_text = f"{RED}Offline{RESET}"
                export_status = "Offline"

        with lock:
            if not quiet:
                print(f"IP {ip} -> {status_text}")
            results.append((str(ip), export_status))

    except Exception as e:
        with lock:
            if not quiet:
                print(f"{RED}[ERRO]{RESET} Falha ao verificar {ip}: {e}")
            results.append((str(ip), "Erro"))


def worker(quiet):
    while not queue.empty():
        ip = queue.get()
        check_host(ip, quiet)
        queue.task_done()


def scan_network(network, threads=50, output="scan_result.csv", quiet=False):
    net = ipaddress.ip_network(network, strict=False)
    if not quiet:
        print(f"Iniciando varredura em {network} com {threads} threads...")

    for ip in net.hosts():
        queue.put(ip)

    for _ in range(threads):
        t = threading.Thread(target=worker, args=(quiet,))
        t.daemon = True
        t.start()

    queue.join()

    # Exporta CSV
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Status"])
        writer.writerows(results)

    if not quiet:
        print(f"\n{GREEN}[OK]{RESET} Varredura concluída. Resultados salvos em {output}")


def main():
    parser = argparse.ArgumentParser(description="Scanner de Rede com Exportação CSV e Códigos de Cores")
    parser.add_argument("target", help="Rede ou IP alvo (ex: 192.168.1.0/24 ou 192.168.1.10)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de threads (default: 50)")
    parser.add_argument("-o", "--output", default="scan_result.csv", help="Arquivo de saída CSV")
    parser.add_argument("--quiet", action="store_true", help="Executa em modo silencioso (sem saída no terminal)")
    parser.add_argument("--version", action="version", version="Scanner v1.1")

    args = parser.parse_args()

    try:
        scan_network(args.target, threads=args.threads, output=args.output, quiet=args.quiet)
    except KeyboardInterrupt:
        if not args.quiet:
            print(f"\n{YELLOW}[!] Varredura interrompida pelo usuário{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()

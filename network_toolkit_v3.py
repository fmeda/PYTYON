import argparse
import subprocess
import json
import platform
import threading
import socket
from scapy.all import ARP, Ether, srp, sniff
import os

def save_to_file(data, filename, message):
    filepath = os.path.abspath(filename)
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    print(f"\n📁 {message} O arquivo foi salvo em: {filepath}")

def ping(host):
    print(f"\n🔄 Pingando {host}...")
    result = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)
    output = result.stdout
    save_to_file(output, f"ping_{host}.json", f"✅ Teste de ping em {host} concluído!")

def scan_ports(host, ports):
    print(f"\n🔍 Escaneando portas {ports} em {host}...")

    def scan(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    open_ports = []
    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    save_to_file({"host": host, "open_ports": open_ports}, f"scan_ports_{host}.json", f"✅ Escaneamento de portas em {host} concluído!")

def analyze_network(interface):
    print(f"\n📡 Analisando tráfego na interface {interface}...")
    packets = sniff(iface=interface, count=10)
    output = str(packets)
    save_to_file(output, "network_traffic.json", "✅ Análise de tráfego concluída!")

def detect_devices(network):
    print(f"\n🔎 Detectando dispositivos na rede {network}...")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = [{"IP": received.psrc, "MAC": received.hwsrc} for sent, received in result]
    save_to_file(devices, "devices.json", "✅ Detecção de dispositivos concluída!")

def list_installed_programs():
    print("\n📂 Listando programas instalados...")
    programs = []

    if platform.system() == "Windows":
        result = subprocess.run(["wmic", "product", "get", "name"], capture_output=True, text=True)
        programs = [line.strip() for line in result.stdout.split("\n") if line.strip()]
    elif platform.system() == "Linux":
        result = subprocess.run(["dpkg", "--list"], capture_output=True, text=True)
        programs = [line.split()[1] for line in result.stdout.split("\n") if line.startswith("ii")]

    save_to_file(programs, "installed_programs.json", "✅ Listagem de programas concluída!")

def list_drivers():
    print("\n🔧 Listando drivers instalados...")
    drivers = []

    if platform.system() == "Windows":
        result = subprocess.run(["wmic", "sysdriver", "get", "name"], capture_output=True, text=True)
        drivers = [line.strip() for line in result.stdout.split("\n") if line.strip()]
    elif platform.system() == "Linux":
        result = subprocess.run(["lsmod"], capture_output=True, text=True)
        drivers = [line.split()[0] for line in result.stdout.split("\n") if line]

    save_to_file(drivers, "installed_drivers.json", "✅ Listagem de drivers concluída!")

def execute_all_tests(hosts, network, interface, ports):
    for host in hosts:
        ping(host)
        scan_ports(host, ports)
    analyze_network(interface)
    detect_devices(network)
    list_installed_programs()
    list_drivers()

def show_menu():
    while True:
        print("\n🚀 MENU PRINCIPAL")
        print("[1] Testar Ping")
        print("[2] Escanear Portas")
        print("[3] Analisar Tráfego de Rede")
        print("[4] Detectar Dispositivos na Rede")
        print("[5] Listar Programas Instalados")
        print("[6] Listar Drivers Instalados")
        print("[7] Executar Todos os Testes (Remoto)")
        print("[0] Sair")

        choice = input("\nDigite a opção desejada: ")

        if choice == "1":
            host = input("Digite o endereço de host: ")
            ping(host)
        elif choice == "2":
            host = input("Digite o endereço de host: ")
            ports = list(map(int, input("Digite as portas separadas por espaço: ").split()))
            scan_ports(host, ports)
        elif choice == "3":
            interface = input("Digite a interface de rede (ex: eth0): ")
            analyze_network(interface)
        elif choice == "4":
            network = input("Digite a rede (ex: 192.168.1.0/24): ")
            detect_devices(network)
        elif choice == "5":
            list_installed_programs()
        elif choice == "6":
            list_drivers()
        elif choice == "7":
            hosts = input("Digite os hosts separados por espaço: ").split()
            network = input("Digite a rede para detectar dispositivos (ex: 192.168.1.0/24): ")
            interface = input("Digite a interface de rede para análise de tráfego (ex: eth0): ")
            ports = list(map(int, input("Digite as portas para escanear separadas por espaço: ").split()))
            execute_all_tests(hosts, network, interface, ports)
        elif choice == "0":
            print("\n👋 Saindo... Até mais!")
            break
        else:
            print("❌ Opção inválida. Tente novamente.")

if __name__ == "__main__":
    show_menu()

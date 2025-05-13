import os
import time
import csv
from netmiko import ConnectHandler
from datetime import datetime
from getpass import getpass

# Função para solicitar as credenciais e dados do analista
def get_device_credentials():
    devices = []
    while True:
        try:
            num_devices = int(input("Quantos dispositivos Cisco deseja configurar? "))
            if num_devices < 1:
                print("O número de dispositivos deve ser maior que zero.")
                continue
            break
        except ValueError:
            print("Digite um número válido.")

    for i in range(num_devices):
        print(f"\nConfigurações do dispositivo {i+1}:")
        device = {
            'host': input("Endereço IP ou hostname do dispositivo: "),
            'username': input("Nome de usuário para SSH: "),
            'password': getpass("Senha para o usuário: "),  # Senha protegida
            'secret': getpass("Senha de enable (se necessário): "),  # Senha de enable protegida
            'device_type': 'cisco_ios',
            'timeout': 30  # Adicionando tempo limite de conexão
        }
        devices.append(device)
    
    return devices

# Função para backup da configuração
def backup_config(device):
    net_connect = None  
    try:
        print(f"Iniciando backup de configuração para {device['host']}...")
        net_connect = ConnectHandler(**device)
        net_connect.enable()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_file = f"backup-config-{device['host']}-{timestamp}.cfg"
        
        output = net_connect.send_command("show running-config")
        with open(backup_file, "w") as f:
            f.write(output)
        
        print(f"Backup realizado para {device['host']} -> {backup_file}")
        return True
    except Exception as e:
        print(f"Erro ao realizar backup em {device['host']}: {e}")
        return False
    finally:
        if net_connect:
            net_connect.disconnect()

# Função para atualização do IOS
def update_ios(device, ios_image):
    net_connect = None
    try:
        print(f"Iniciando atualização de IOS em {device['host']}...")
        net_connect = ConnectHandler(**device)
        net_connect.enable()
        
        output = net_connect.send_command(f"copy tftp://10.150.1.10/{ios_image} flash:")
        print(f"Imagem {ios_image} copiada para {device['host']}")

        # Verificando a imagem com checksum
        checksum_output = net_connect.send_command(f"verify /md5 flash:{ios_image}")
        print(f"Checksum para {ios_image}: {checksum_output}")

        net_connect.send_config_set([f"boot system flash:{ios_image}"])
        print(f"Configuração de boot para {ios_image} aplicada em {device['host']}")

        net_connect.send_command("write memory")
        print(f"Configurações salvas em {device['host']}")
        
        return True
    except Exception as e:
        print(f"Erro ao atualizar IOS em {device['host']}: {e}")
        return False
    finally:
        if net_connect:
            net_connect.disconnect()

# Função para configurar portas e protocolos
def configure_ports_protocols(device):
    net_connect = None
    try:
        print(f"Iniciando configuração de portas e protocolos em {device['host']}...")
        net_connect = ConnectHandler(**device)
        net_connect.enable()

        commands = [
            "interface range GigabitEthernet1/0/1 - 48",
            "switchport mode access",
            "switchport access vlan 50",
            "spanning-tree portfast",
            "exit",
            "interface Vlan50",
            "ip address 192.168.50.1 255.255.255.0",
            "no shutdown",
            "exit"
        ]
        net_connect.send_config_set(commands)
        print(f"Configuração de VLAN aplicada em {device['host']}")

        snmp_commands = [
            "snmp-server group SECUREGROUP v3 priv read SECUREVIEW write SECURECHANGE",
            "snmp-server user snmpadmin SECUREGROUP v3 auth md5 AuthPass123 priv aes 256 PrivPass123"
        ]
        net_connect.send_config_set(snmp_commands)
        print(f"SNMPv3 configurado em {device['host']}")

        net_connect.send_command("write memory")
        print(f"Configurações salvas em {device['host']}")
        
        return True
    except Exception as e:
        print(f"Erro ao configurar portas em {device['host']}: {e}")
        return False
    finally:
        if net_connect:
            net_connect.disconnect()

# Função para gerar relatório
def generate_report(status, device, task):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("automation_report.csv", mode="a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, device['host'], task, status])

# Função principal para execução
def main():
    devices = get_device_credentials()

    with open("automation_report.csv", mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Device", "Task", "Status"])

    for device in devices:
        backup_status = backup_config(device)
        generate_report("Success" if backup_status else "Failed", device, "Backup Config")
        
        if backup_status:
            ios_status = update_ios(device, "c2960x-universalk9-mz.152-7.E3.bin")
            generate_report("Success" if ios_status else "Failed", device, "Update IOS")
            
            config_status = configure_ports_protocols(device)
            generate_report("Success" if config_status else "Failed", device, "Configure Ports & Protocols")

if __name__ == "__main__":
    main()

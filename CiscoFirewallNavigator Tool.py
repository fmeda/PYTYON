import os
import random
import time
import json

# Função para carregar o estado dos serviços a partir de um arquivo
def carregar_estado_servicos():
    if os.path.exists('estado_servicos.json'):
        with open('estado_servicos.json', 'r') as file:
            return json.load(file)
    else:
        # Retorna estado inicial se o arquivo não existir
        return {
            "Cisco ASA Firewall": "Inativo",
            "Cisco Firepower": "Inativo",
            "Regras de Bloqueio": "Inativo",
            "Segurança de VPN": "Inativo"
        }

# Função para salvar o estado dos serviços em um arquivo
def salvar_estado_servicos(estado):
    with open('estado_servicos.json', 'w') as file:
        json.dump(estado, file, indent=4)

# Função para simular o status dos serviços
def status_service(service, estado):
    return estado.get(service, "Inativo")

# Função para simular eventos de segurança
def security_alert():
    alerts = [
        "[ALERTA]: Tentativa de intrusão - IP 192.168.1.100",
        "[ALERTA]: Tráfego anômalo detectado - IP 10.0.0.5",
        "[ALERTA]: Tentativa de login mal-sucedida - IP 10.1.1.25",
        "[ALERTA]: Ataque DDoS detectado - IP 172.16.0.8",
        "[ALERTA]: Recurso VPN bloqueado - IP 192.168.1.200",
        "[ALERTA]: Ataque SYN Flood detectado - IP 172.16.1.50",
        "[ALERTA]: Port Scanning detectado - IP 10.10.10.10",
        "[ALERTA]: Brute Force detectado - IP 10.0.1.30"
    ]
    return random.choice(alerts)

# Função para exibir o menu principal
def menu_principal():
    print("CiscoFirewallNavigator - Menu Principal")
    print("1. Segurança de Perímetro e Proteção de Rede")
    print("2. Gerenciamento de Regras de Firewall")
    print("3. Monitoramento de Tráfego e Análise de Logs")
    print("4. Simulação e Prevenção de Ameaças")
    print("5. Configuração de Políticas de Segurança")
    print("6. Monitorar Eventos de Segurança")
    print("7. Conectividade e Acesso Remoto")
    print("8. Planejamento, Gestão e Implementação de Firewall")
    print("9. Sair do Programa")
    print("\n[Pressione 'q' para sair do menu]")

# Função para exibir submenu de serviços de firewall
def submenu_servicos_firewall(estado):
    print("\nSegurança de Perímetro e Proteção de Rede - Escolha um serviço (Pressione 't' para ativar/desativar):\n")
    services = [
        "Cisco ASA Firewall",
        "Cisco Firepower",
        "Regras de Bloqueio",
        "Segurança de VPN"
    ]
    
    for service in services:
        status = status_service(service, estado)
        status_color = "✅" if status == "Ativo" else "❌"
        print(f"{service} ({status_color} {status})")
    
    print("\n[Pressione 'b' para voltar]")

# Função para monitorar eventos de segurança
def monitorar_eventos():
    print("\nMonitorando Eventos de Segurança...\n")
    for _ in range(3):  # Simula 3 eventos de segurança
        print(security_alert())
        time.sleep(2)
    input("\nPressione 'Enter' para continuar...")

# Função principal para controlar o programa
def run_program():
    estado_servicos = carregar_estado_servicos()
    
    while True:
        os.system('clear')  # Limpa a tela (Linux/Mac) ou 'cls' (Windows)
        menu_principal()
        
        choice = input("\nEscolha uma opção: ").strip().lower()
        
        if choice == 'q':
            print("\nSaindo do programa...")
            break
        elif choice == '1':
            submenu_servicos_firewall(estado_servicos)
            action = input("\nEscolha uma ação (Pressione 'b' para voltar ou 't' para ativar/desativar): ").strip().lower()
            if action == 'b':
                continue
            elif action == 't':
                service = input("\nDigite o nome do serviço para ativar/desativar: ").strip()
                if service in estado_servicos:
                    estado_servicos[service] = "Ativo" if estado_servicos[service] == "Inativo" else "Inativo"
                    print(f"\n{service} foi {'Ativado' if estado_servicos[service] == 'Ativo' else 'Desativado'} com sucesso!\n")
                    salvar_estado_servicos(estado_servicos)  # Salva o novo estado
                else:
                    print("\nServiço não encontrado.\n")
            else:
                print("\nAção inválida!\n")
        elif choice == '2':
            print("\nGerenciamento de Regras de Firewall...")
            input("\nPressione 'Enter' para continuar...")
        elif choice == '3':
            print("\nMonitoramento de Tráfego e Análise de Logs...")
            input("\nPressione 'Enter' para continuar...")
        elif choice == '4':
            print("\nSimulação e Prevenção de Ameaças...")
            input("\nPressione 'Enter' para continuar...")
        elif choice == '5':
            print("\nConfiguração de Políticas de Segurança...")
            input("\nPressione 'Enter' para continuar...")
        elif choice == '6':
            monitorar_eventos()
        elif choice == '7':
            print("\nConectividade e Acesso Remoto...")
            input("\nPressione 'Enter' para continuar...")
        elif choice == '8':
            print("\nPlanejamento, Gestão e Implementação de Firewall...")
            input("\nPressione 'Enter' para continuar...")
        else:
            print("\nOpção inválida! Tente novamente.")
            time.sleep(1)

# Iniciar o programa
if __name__ == "__main__":
    run_program()

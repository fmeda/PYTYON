import time
import random
import os

# Função para limpar a tela
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Função para simular o status dos serviços e VPNs
def update_service_status():
    services = {
        'Cisco Firepower': random.choice([True, False]),
        'Cisco Umbrella': random.choice([True, False]),
        'Cisco ISE': random.choice([True, False]),
        'Cisco Meraki': random.choice([True, False]),
        'VPN Service': random.choice([True, False]),  # Novo serviço VPN
    }
    return services

# Função para monitorar eventos de segurança
def monitor_security_events():
    events = [
        'Intrusão detectada - IP 192.168.1.100',
        'Falha de autenticação - Tentativa de login mal-sucedida',
        'Ataque DDoS detectado - Tráfego anômalo',
        'Conexão VPN estabelecida com sucesso'
    ]
    return random.choice(events)

# Função para exibir o menu de serviços
def show_service_menu(services):
    clear_screen()
    print("Segurança de Perímetro e Proteção de Rede - Escolha um serviço (Pressione 't' para ativar/desativar):\n")
    
    for idx, (service, status) in enumerate(services.items(), 1):
        status_str = 'Ativo' if status else 'Inativo'
        status_icon = '✅' if status else '❌'
        print(f"{idx}. {service} ({status_str}) {status_icon}")
    
    print("\n[Pressione 'b' para voltar]")

# Função para ativar ou desativar serviço
def toggle_service(services, service_idx):
    service_name = list(services.keys())[service_idx - 1]
    services[service_name] = not services[service_name]
    print(f"Status do serviço '{service_name}' alterado para {'Ativo' if services[service_name] else 'Inativo'}.")

# Função para exibir o menu principal
def show_main_menu():
    clear_screen()
    print("CiscoNavigator - Menu Principal")
    print("1. Segurança de Perímetro e Proteção de Rede")
    print("2. Proteção de Endpoints e Identidade")
    print("3. Segurança de Aplicações e Dados")
    print("4. Inteligência Artificial e Automação em Segurança")
    print("5. Monitoramento e Análise de Segurança")
    print("6. Simulação e Prevenção de Ameaças")
    print("7. Conectividade Segura e Infraestrutura")
    print("8. Planejamento, Gestão e Implementação de Segurança")
    print("9. Monitorar Eventos de Segurança")
    print("10. Sair do Programa\n")
    print("[Pressione 'q' para sair do menu]")

# Função para exibir eventos de segurança em tempo real
def display_security_events():
    event = monitor_security_events()
    print(f"\n[ALERTA]: {event}")
    time.sleep(2)

# Função principal para rodar o programa
def run_cisco_navigator():
    while True:
        show_main_menu()
        choice = input("\nEscolha uma opção: ").strip().lower()

        if choice == 'q':
            print("Saindo do programa...")
            break
        elif choice == '1':
            services = update_service_status()  # Atualiza o status dos serviços
            while True:
                show_service_menu(services)
                service_choice = input("\nEscolha o serviço ou pressione 'b' para voltar: ").strip().lower()
                
                if service_choice == 'b':
                    break
                elif service_choice == 't':
                    try:
                        service_idx = int(input("Digite o número do serviço para ativar/desativar: "))
                        if 1 <= service_idx <= len(services):
                            toggle_service(services, service_idx)
                        else:
                            print("Opção inválida, tente novamente.")
                    except ValueError:
                        print("Entrada inválida, tente novamente.")
                else:
                    print("Opção inválida, tente novamente.")
                time.sleep(1)
        elif choice == '9':
            display_security_events()  # Exibe um evento de segurança em tempo real
        else:
            print("Opção inválida, tente novamente.")
        time.sleep(1)

if __name__ == "__main__":
    run_cisco_navigator()

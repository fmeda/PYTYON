from utils import clear_screen, log_action

def security_menu():
    """Menu de configuração de segurança"""
    while True:
        clear_screen()
        print("=== Configuração de Segurança ===")
        print("1. Configurar Azure Key Vault")
        print("2. Configurar Azure Firewall")
        print("3. Configurar MFA")
        print("4. Voltar ao Menu Principal")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            log_action("Iniciando configuração do Azure Key Vault...")
            configure_key_vault()
        elif choice == '2':
            log_action("Iniciando configuração do Azure Firewall...")
            configure_firewall()
        elif choice == '3':
            log_action("Habilitando MFA...")
            enable_mfa()
        elif choice == '4':
            break
        else:
            print("\nOpção inválida! Tente novamente.")
            input("\nPressione Enter para continuar...")

def configure_key_vault():
    """Configura o Azure Key Vault"""
    print("\nConfigurando Azure Key Vault...")
    # Insira lógica aqui
    log_action("Azure Key Vault configurado.")

def configure_firewall():
    """Configura o Azure Firewall"""
    print("\nConfigurando Azure Firewall...")
    # Insira lógica aqui
    log_action("Azure Firewall configurado.")

def enable_mfa():
    """Habilita MFA no Azure"""
    print("\nHabilitando MFA...")
    # Insira lógica aqui
    log_action("MFA habilitado.")

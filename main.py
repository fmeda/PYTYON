from utils import clear_screen, setup_logging, check_dependencies
import validation
import security
import advanced_features

def main_menu():
    """Menu principal"""
    while True:
        clear_screen()
        print("=== Azure Validation CLI ===")
        print("1. Validação Básica")
        print("2. Configuração de Segurança")
        print("3. Recursos Avançados")
        print("4. Sair")
        choice = input("\nEscolha uma opção: ")

        if choice == '1':
            validation.validation_menu()
        elif choice == '2':
            security.security_menu()
        elif choice == '3':
            advanced_features.advanced_features_menu()
        elif choice == '4':
            print("\nSaindo... Até mais!")
            break
        else:
            print("\nOpção inválida! Tente novamente.")
            input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    setup_logging()
    check_dependencies()
    main_menu()

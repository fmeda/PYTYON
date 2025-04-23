import getpass
import os
import pandas as pd
from cryptography.fernet import Fernet

# Gerar ou carregar chave de criptografia
def carregar_chave():
    chave_arquivo = "chave.key"
    if not os.path.exists(chave_arquivo):
        chave = Fernet.generate_key()
        with open(chave_arquivo, "wb") as arquivo:
            arquivo.write(chave)
    else:
        with open(chave_arquivo, "rb") as arquivo:
            chave = arquivo.read()
    return chave

# Criptografia e descriptografia
def criptografar_dados(dados, chave):
    fernet = Fernet(chave)
    return fernet.encrypt(dados.encode())

def descriptografar_dados(dados_criptografados, chave):
    fernet = Fernet(chave)
    return fernet.decrypt(dados_criptografados).decode()

# Alterar senha do administrador no primeiro login
def alterar_senha():
    print("\n=== Alteração de Senha ===")
    nova_senha = getpass.getpass("Digite sua nova senha: ")
    confirmar_senha = getpass.getpass("Confirme sua nova senha: ")
    
    if nova_senha == confirmar_senha:
        print("Senha alterada com sucesso!")
        return nova_senha
    else:
        print("As senhas não coincidem. Tente novamente.")
        return alterar_senha()

# Autenticação inicial com alteração de senha
def autenticar_usuario():
    print("\n=== Módulo de Segurança ===")
    username = input("Digite seu nome de usuário: ")
    password = getpass.getpass("Digite sua senha: ")
    
    if username == "admin" and password == "senha_segura":
        print("Autenticação bem-sucedida! Você precisa alterar sua senha.")
        return alterar_senha()
    else:
        print("Credenciais inválidas. Encerrando o programa.\n")
        return None

# Solicitar caminho de saída
def solicitar_caminho_saida():
    print("\nEscolha o diretório onde os relatórios serão salvos.")
    caminho = input("Digite o caminho completo (exemplo: C:\\Relatorios): ")
    if not os.path.exists(caminho):
        os.makedirs(caminho)
        print(f"Diretório {caminho} criado.\n")
    else:
        print(f"Salvando relatórios em: {caminho}\n")
    return caminho

def salvar_relatorio(nome_arquivo, dados, caminho, extensao):
    arquivo_completo = os.path.join(caminho, f"{nome_arquivo}.{extensao}")
    if extensao == "xlsx":
        dados.to_excel(arquivo_completo, index=False)
    elif extensao == "csv":
        dados.to_csv(arquivo_completo, index=False)
    print(f"Relatório salvo em: {arquivo_completo}\n")

def gerar_relatorio_exemplo(nome, caminho, extensao):
    print(f"Gerando {nome}...\n")
    dados = pd.DataFrame({
        "Coluna 1": ["A", "B", "C"],
        "Coluna 2": [1, 2, 3],
        "Coluna 3": [4.5, 5.5, 6.5]
    })
    salvar_relatorio(nome, dados, caminho, extensao)

# Menu do programa
def exibir_menu():
    print("\n=== Menu de Relatórios ===")
    print("1. Configurar Servidores")
    print("2. Relatório de Integridade e Disponibilidade")
    print("3. Relatório de Segurança e Tendências")
    print("4. Relatório de Vulnerabilidades e Impacto Operacional")
    print("5. Relatório de Conformidade e Inventário")
    print("6. Relatório de Incidentes Integrado")
    print("7. Relatório de Saúde Geral")
    print("8. Executar Todos os Relatórios")
    print("9. Sair")
    print("==========================")

def executar_programa():
    print("Bem-vindo ao Sistema de Relatórios CLI!\n")
    nova_senha = autenticar_usuario()
    if not nova_senha:
        return
    
    chave = carregar_chave()
    dados_servidores = None
    caminho_saida = solicitar_caminho_saida()
    extensao = input("Escolha a extensão do relatório (xlsx para Excel, csv para Power BI): ").lower()
    while extensao not in ["xlsx", "csv"]:
        print("Extensão inválida. Escolha 'xlsx' ou 'csv'.")
        extensao = input("Digite novamente: ").lower()

    while True:
        exibir_menu()
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            dados_servidores = coletar_dados_servidor(chave)
        elif opcao == "2":
            gerar_relatorio_exemplo("Relatorio_Integridade_Disponibilidade", caminho_saida, extensao)
        elif opcao == "3":
            gerar_relatorio_exemplo("Relatorio_Seguranca_Tendencias", caminho_saida, extensao)
        elif opcao == "4":
            gerar_relatorio_exemplo("Relatorio_Vulnerabilidades_Impacto", caminho_saida, extensao)
        elif opcao == "5":
            gerar_relatorio_exemplo("Relatorio_Conformidade_Inventario", caminho_saida, extensao)
        elif opcao == "6":
            gerar_relatorio_exemplo("Relatorio_Incidentes_Integrado", caminho_saida, extensao)
        elif opcao == "7":
            gerar_relatorio_exemplo("Relatorio_Saude_Geral", caminho_saida, extensao)
        elif opcao == "8":
            print("\nExecutando todos os relatórios...\n")
            gerar_relatorio_exemplo("Relatorio_Integridade_Disponibilidade", caminho_saida, extensao)
            gerar_relatorio_exemplo("Relatorio_Seguranca_Tendencias", caminho_saida, extensao)
            gerar_relatorio_exemplo("Relatorio_Vulnerabilidades_Impacto", caminho_saida, extensao)
            gerar_relatorio_exemplo("Relatorio_Conformidade_Inventario", caminho_saida, extensao)
            gerar_relatorio_exemplo("Relatorio_Incidentes_Integrado", caminho_saida, extensao)
            gerar_relatorio_exemplo("Relatorio_Saude_Geral", caminho_saida, extensao)
        elif opcao == "9":
            print("Encerrando o programa. Até mais!\n")
            break
        else:
            print("Opção inválida. Tente novamente.\n")

# Executa o programa
executar_programa()

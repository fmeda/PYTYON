#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import getpass
import subprocess
import importlib
from pathlib import Path
from datetime import datetime
import hashlib
import pandas as pd
from cryptography.fernet import Fernet
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------
# Pre-check e instalação de pacotes
# ------------------------
required_packages = ["pandas", "cryptography", "colorama", "openpyxl"]
for pkg in required_packages:
    try:
        importlib.import_module(pkg)
    except ImportError:
        print(f"[INFO] Biblioteca '{pkg}' não encontrada. Instalando...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# ------------------------
# Variáveis globais seguras
# ------------------------
TEMP_PASSWORD = None
AUDIT_LOG_FILE = "audit_log.txt"

# ------------------------
# Funções de auditoria
# ------------------------
def log_auditoria(acao, usuario="admin", status="SUCESSO"):
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | USUARIO: {usuario} | ACAO: {acao} | STATUS: {status}\n")

# ------------------------
# Criptografia tripla
# ------------------------
def carregar_chave():
    chave_file = "chave.key"
    if not os.path.exists(chave_file):
        chave = Fernet.generate_key()
        with open(chave_file, "wb") as f:
            f.write(chave)
        print(Fore.GREEN + "[INFO] Chave de criptografia gerada.")
    else:
        with open(chave_file, "rb") as f:
            chave = f.read()
        print(Fore.GREEN + "[INFO] Chave carregada.")
    return chave

def criptografar_dados(dados, chave):
    fernet = Fernet(chave)
    dados_cript = fernet.encrypt(dados.encode())
    hash_sha = hashlib.sha256(dados.encode()).hexdigest()
    return f"{dados_cript.decode()}||{hash_sha}"

def descriptografar_dados(dados_criptografados, chave):
    fernet = Fernet(chave)
    dados_enc, hash_sha = dados_criptografados.split("||")
    dados_dec = fernet.decrypt(dados_enc.encode()).decode()
    if hashlib.sha256(dados_dec.encode()).hexdigest() != hash_sha:
        raise ValueError("Falha de integridade dos dados!")
    return dados_dec

# ------------------------
# Segurança e autenticação
# ------------------------
def alterar_senha():
    global TEMP_PASSWORD
    print(Fore.CYAN + "\n=== Alteração de Senha ===")
    nova_senha = getpass.getpass("Digite sua nova senha temporária para esta sessão: ")
    confirmar_senha = getpass.getpass("Confirme sua senha: ")
    if nova_senha == confirmar_senha:
        TEMP_PASSWORD = nova_senha
        print(Fore.GREEN + "Senha alterada e armazenada com segurança durante a sessão!")
        log_auditoria("ALTERACAO_SENHA")
        return TEMP_PASSWORD
    else:
        print(Fore.RED + "As senhas não coincidem. Tente novamente.")
        return alterar_senha()

def autenticar_usuario():
    print(Fore.CYAN + "\n=== Módulo de Segurança ===")
    username = input("Digite seu nome de usuário: ")
    password = getpass.getpass("Digite sua senha inicial: ")
    if username == "admin" and password == "senha_segura":
        print(Fore.GREEN + "Autenticação bem-sucedida! Alteração de senha obrigatória.")
        log_auditoria("LOGIN_SUCESSO", usuario=username)
        return alterar_senha()
    else:
        print(Fore.RED + "Credenciais inválidas. Encerrando o programa.")
        log_auditoria("LOGIN_FALHA", usuario=username, status="FALHA")
        return None

# ------------------------
# Relatórios refinados
# ------------------------
def solicitar_caminho_saida():
    print(Fore.CYAN + "\nEscolha o diretório onde os relatórios serão salvos.")
    caminho = input("Digite o caminho completo: ")
    caminho_path = Path(caminho)
    caminho_path.mkdir(parents=True, exist_ok=True)
    print(Fore.GREEN + f"Diretório definido: {caminho_path}")
    return str(caminho_path)

def salvar_relatorio(nome, dados, caminho, extensao, chave):
    arquivo_completo = os.path.join(caminho, f"{nome}.{extensao}")
    try:
        if extensao == "xlsx":
            with pd.ExcelWriter(arquivo_completo, engine="openpyxl") as writer:
                dados.to_excel(writer, index=False, sheet_name="Relatório")
                worksheet = writer.sheets["Relatório"]
                for col in worksheet.columns:
                    max_length = max(len(str(cell.value)) for cell in col)
                    worksheet.column_dimensions[col[0].column_letter].width = max_length + 2
        else:
            dados.to_csv(arquivo_completo, index=False, encoding="utf-8")
        # Criptografar arquivo
        with open(arquivo_completo, "r", encoding="utf-8") as f:
            conteudo = f.read()
        with open(f"{arquivo_completo}.enc", "w", encoding="utf-8") as f:
            f.write(criptografar_dados(conteudo, chave))
        log_auditoria(f"RELATORIO_GERADO: {nome}")
        print(Fore.GREEN + f"Relatório salvo e criptografado: {arquivo_completo}.enc")
    except Exception as e:
        log_auditoria(f"ERRO_RELATORIO: {nome}", status="FALHA")
        print(Fore.RED + f"[ERRO] Falha ao gerar relatório: {e}")

def gerar_relatorio_exemplo(nome, caminho, extensao, chave):
    print(Fore.YELLOW + f"\nGerando {nome}...")
    dados = pd.DataFrame({
        "ID Relatório": [f"{nome[:3].upper()}-{i+1}" for i in range(3)],
        "Data de Geração": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")]*3,
        "Sistema": ["ERP", "CRM", "Firewall"],
        "Status Operacional": ["Ok", "Alerta", "Crítico"],
        "Risco CMNI": ["Baixo", "Médio", "Alto"],
        "Conformidade PEP": ["Sim", "Não", "Sim"],
        "Responsável": ["TI", "SOC", "Auditoria"]
    })
    salvar_relatorio(nome, dados, caminho, extensao, chave)

# ------------------------
# Menu CLI
# ------------------------
def exibir_menu():
    print(Fore.CYAN + "\n=== Menu de Relatórios 2025 ===")
    print("1. Configurar Servidores (CMNI/PEP)")
    print("2. Relatório Integridade/Disponibilidade")
    print("3. Relatório Segurança/Tendências")
    print("4. Relatório Vulnerabilidades/Impacto")
    print("5. Relatório Conformidade/Inventário")
    print("6. Relatório Incidentes Integrado")
    print("7. Relatório Saúde Geral")
    print("8. Executar Todos os Relatórios")
    print("9. Sair")
    print("10. HELP (detalhes dos relatórios)")
    print("===============================")

def exibir_help_relatorios():
    print(Fore.CYAN + "\n=== Ajuda Detalhada dos Relatórios ===")
    print("""
1. Configurar Servidores (CMNI/PEP)
   - Objetivo: Preparar os servidores para coleta de dados de auditoria e conformidade.
   - Aplicação: Análise CMNI e PEP para integridade de sistemas e políticas.

2. Relatório Integridade/Disponibilidade
   - Objetivo: Avaliar a disponibilidade de sistemas críticos e integridade de dados.
   - Aplicação: Detecta falhas operacionais, downtime e inconsistências.

3. Relatório Segurança/Tendências
   - Objetivo: Monitorar eventos de segurança e identificar tendências.
   - Aplicação: Suporte a decisões de SOC e mitigação de riscos cibernéticos.

4. Relatório Vulnerabilidades/Impacto
   - Objetivo: Listar vulnerabilidades detectadas e seu impacto operacional.
   - Aplicação: Base para priorização de correções e gestão de riscos.

5. Relatório Conformidade/Inventário
   - Objetivo: Inventariar ativos e validar conformidade com políticas internas.
   - Aplicação: Facilita auditorias internas e externas (CMNI/PEP).

6. Relatório Incidentes Integrado
   - Objetivo: Consolidar incidentes de sistemas e rede.
   - Aplicação: Análise de incidentes, prevenção e lições aprendidas.

7. Relatório Saúde Geral
   - Objetivo: Fornecer visão geral da saúde dos sistemas e infraestrutura.
   - Aplicação: Indicadores de desempenho, uptime e métricas operacionais.

8. Executar Todos os Relatórios
   - Objetivo: Gerar todos os relatórios sequencialmente.
   - Aplicação: Auditoria completa, revisão operacional e compliance geral.
""")

# ------------------------
# Main
# ------------------------
def executar_programa():
    try:
        print(Fore.MAGENTA + "Bem-vindo ao Sistema de Relatórios CLI 2025!")
        if not autenticar_usuario():
            return

        chave = carregar_chave()
        caminho_saida = solicitar_caminho_saida()
        extensao = input("Escolha a extensão do relatório (xlsx/csv): ").lower()
        while extensao not in ["xlsx", "csv"]:
            print(Fore.RED + "Extensão inválida.")
            extensao = input("Digite novamente (xlsx/csv): ").lower()

        while True:
            exibir_menu()
            opcao = input("Escolha uma opção: ")

            if opcao == "1":
                print(Fore.YELLOW + "[Módulo CMNI/PEP] Configuração de servidores em desenvolvimento.")
            elif opcao == "2":
                gerar_relatorio_exemplo("Integridade_Disponibilidade", caminho_saida, extensao, chave)
            elif opcao == "3":
                gerar_relatorio_exemplo("Seguranca_Tendencias", caminho_saida, extensao, chave)
            elif opcao == "4":
                gerar_relatorio_exemplo("Vulnerabilidades_Impacto", caminho_saida, extensao, chave)
            elif opcao == "5":
                gerar_relatorio_exemplo("Conformidade_Inventario", caminho_saida, extensao, chave)
            elif opcao == "6":
                gerar_relatorio_exemplo("Incidentes_Integrado", caminho_saida, extensao, chave)
            elif opcao == "7":
                gerar_relatorio_exemplo("Saude_Geral", caminho_saida, extensao, chave)
            elif opcao == "8":
                for nome in ["Integridade_Disponibilidade", "Seguranca_Tendencias",
                             "Vulnerabilidades_Impacto", "Conformidade_Inventario",
                             "Incidentes_Integrado", "Saude_Geral"]:
                    gerar_relatorio_exemplo(nome, caminho_saida, extensao, chave)
            elif opcao == "9":
                print(Fore.GREEN + "Encerrando. Até mais!")
                break
            elif opcao == "10":
                exibir_help_relatorios()
            else:
                print(Fore.RED + "Opção inválida.")

    except KeyboardInterrupt:
        print(Fore.RED + "\n[INFO] Programa interrompido pelo usuário (CTRL+C). Encerrando...")
    except Exception as e:
        print(Fore.RED + f"[ERRO CRÍTICO] {e}")
    finally:
        print(Fore.MAGENTA + "Sessão encerrada.")

# ------------------------
# Execução
# ------------------------
if __name__ == "__main__":
    executar_programa()

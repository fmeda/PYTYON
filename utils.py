import os
import logging
import sys
import subprocess

def clear_screen():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def setup_logging():
    """Configura o sistema de logs"""
    logging.basicConfig(filename='azure_cli.log', level=logging.INFO, format='%(asctime)s - %(message)s')
    logging.info("Iniciando o script...")

def log_action(action):
    """Registra uma ação no log"""
    logging.info(action)

def check_dependencies():
    """Verifica dependências e as instala, se necessário"""
    print("Verificando dependências...")
    required_modules = ['os', 'subprocess', 'logging']
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            print(f"Instalando {module}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
    print("Dependências verificadas com sucesso!")

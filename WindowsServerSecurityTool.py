import os
import sys
import logging
import shutil
import ctypes
import subprocess
import importlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import win32security
import win32con
import getpass
import datetime

# Lista de módulos necessários
REQUIRED_MODULES = ["cryptography", "pywin32", "tkinter"]

def check_and_install_modules():
    """Verifica e instala módulos necessários."""
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            print(f"Módulo {module} não encontrado. Instalando...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

# Executa a verificação de módulos antes de iniciar o programa
check_and_install_modules()

# Configuração de logs
logging.basicConfig(filename='security_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_key():
    """Gera uma chave de criptografia e salva em um arquivo."""
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    logging.info("Chave de criptografia gerada com sucesso.")

def load_key():
    """Carrega a chave de criptografia de um arquivo."""
    return open("encryption_key.key", "rb").read()

def backup_file(file_path):
    """Cria um backup do arquivo antes de criptografá-lo."""
    backup_path = file_path + ".backup"
    shutil.copy2(file_path, backup_path)
    logging.info(f"Backup criado: {backup_path}")

def encrypt_file(file_path):
    """Criptografa um arquivo usando a chave gerada, após criar um backup."""
    backup_file(file_path)
    key = load_key()
    cipher = Fernet(key)
    
    with open(file_path, "rb") as file:
        encrypted_data = cipher.encrypt(file.read())
    
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
    
    logging.info(f"Arquivo {file_path} criptografado com sucesso.")

def set_permissions(file_path):
    """Define permissões restritas para um arquivo, incluindo usuários específicos do domínio."""
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = win32security.ACL()
        admin_sid = win32security.LookupAccountName(None, getpass.getuser())[0]
        domain_user_sid, _, _ = win32security.LookupAccountName(None, "DOMAIN\\UsuarioEspecifico")
        
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_READ_DATA, domain_user_sid)
        
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)
        logging.info(f"Permissões aplicadas a {file_path}: Acesso total para admin, leitura para usuário específico do domínio.")
    except Exception as e:
        logging.error(f"Erro ao definir permissões: {str(e)}")

def move_to_protected_directory(file_path):
    """Move um arquivo para um diretório protegido em vez de simplesmente ocultá-lo."""
    protected_dir = "C:\\ProtectedFiles"
    if not os.path.exists(protected_dir):
        os.makedirs(protected_dir)
        logging.info(f"Diretório protegido criado: {protected_dir}")
    
    protected_path = os.path.join(protected_dir, os.path.basename(file_path))
    shutil.move(file_path, protected_path)
    logging.info(f"Arquivo movido para diretório protegido: {protected_path}")

def apply_security_measures(target):
    """Aplica medidas de segurança a um arquivo ou diretório, registrando logs detalhados."""
    logging.info(f"Iniciando aplicação de medidas de segurança em {target} - {datetime.datetime.now()}")
    if os.path.exists(target):
        encrypt_file(target)
        set_permissions(target)
        move_to_protected_directory(target)
        logging.info(f"Medidas de segurança aplicadas com sucesso a {target}")
        messagebox.showinfo("Sucesso", f"Medidas de segurança aplicadas a {target}")
    else:
        logging.error(f"Falha ao aplicar segurança: O caminho especificado não existe: {target}")
        messagebox.showerror("Erro", "Caminho não encontrado.")

def select_file():
    """Abre uma caixa de diálogo para seleção de arquivos."""
    file_path = filedialog.askopenfilename()
    if file_path:
        apply_security_measures(file_path)

def create_gui():
    """Cria uma interface gráfica para facilitar o uso."""
    root = tk.Tk()
    root.title("Ferramenta de Segurança")
    root.geometry("400x200")
    
    label = tk.Label(root, text="Selecione um arquivo para aplicar medidas de segurança:")
    label.pack(pady=10)
    
    select_button = tk.Button(root, text="Selecionar Arquivo", command=select_file)
    select_button.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()

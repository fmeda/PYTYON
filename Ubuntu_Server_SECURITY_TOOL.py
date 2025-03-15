import subprocess
import sys

# Lista de dependências necessárias
required_libraries = [
    'cryptography',
    'paramiko',
    'requests',
    'pyotp'
]

# Função para verificar e instalar dependências
def install_dependencies():
    for lib in required_libraries:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'show', lib])
            print(f"Dependência {lib} já está instalada.")
        except subprocess.CalledProcessError:
            print(f"Dependência {lib} não encontrada. Instalando...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib])
            print(f"Dependência {lib} instalada com sucesso.")

# Verificar dependências antes de iniciar o programa
install_dependencies()

# Código existente após a verificação de dependências
import os
import shutil
import json
import logging
import requests
import paramiko
from cryptography.fernet import Fernet
import pyotp
import time

# Logging setup
logging.basicConfig(filename='/var/log/security_tool.log', level=logging.INFO)

# Função para proteger arquivos e pastas
def set_permissions(file_path, permissions):
    try:
        subprocess.check_call(['chmod', permissions, file_path])
        logging.info(f"Permissions for {file_path} set to {permissions}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set permissions for {file_path}: {e}")
        raise

def set_acl(file_path, acl_rule):
    try:
        subprocess.check_call(['setfacl', '-m', acl_rule, file_path])
        logging.info(f"ACL rule {acl_rule} applied to {file_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set ACL for {file_path}: {e}")
        raise

def make_immutable(file_path):
    try:
        subprocess.check_call(['chattr', '+i', file_path])
        logging.info(f"File {file_path} is now immutable.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to make file immutable {file_path}: {e}")
        raise

# Função para criptografar arquivos
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_data)
    logging.info(f"File {file_path} encrypted.")

# Função para gerar chave de MFA
def generate_mfa_key():
    totp = pyotp.TOTP(pyotp.random_base32())
    mfa_uri = totp.provisioning_uri("security_tool", issuer_name="Admin")
    logging.info("MFA key generated.")
    return totp, mfa_uri

# Função para verificar código MFA
def verify_mfa_code(totp, code):
    if totp.verify(code):
        logging.info("MFA code verified successfully.")
        return True
    else:
        logging.error("Invalid MFA code.")
        return False

# Função para enviar eventos para SIEM
def send_event_to_siem(event_type, message):
    siem_url = 'http://your-siem-url.com'
    payload = {'event_type': event_type, 'message': message}
    try:
        response = requests.post(siem_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        if response.status_code == 200:
            logging.info(f"Event sent to SIEM: {event_type} - {message}")
        else:
            logging.error(f"Failed to send event to SIEM: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending event to SIEM: {e}")
        raise

# Função para realizar backup de arquivos/diretórios
def backup_file(file_path):
    backup_dir = '/backup/'
    try:
        shutil.copy(file_path, backup_dir)
        logging.info(f"File {file_path} backed up to {backup_dir}")
    except IOError as e:
        logging.error(f"Failed to backup {file_path}: {e}")
        raise

# Função para aplicar patches de segurança
def apply_security_patches(server_ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('sudo apt-get update && sudo apt-get upgrade -y')
        stdout.channel.recv_exit_status()
        logging.info(f"Security patches applied on {server_ip}")
        ssh.close()
    except paramiko.SSHException as e:
        logging.error(f"Failed to apply patches on {server_ip}: {e}")
        raise

# Função para gerar e aplicar backups de repositórios
def backup_repositories():
    repo_backup_dir = '/repo_backups/'
    os.makedirs(repo_backup_dir, exist_ok=True)
    try:
        subprocess.check_call(['rsync', '-avz', '--delete', '/etc/apt/sources.list.d/', repo_backup_dir])
        logging.info(f"Repositories backed up to {repo_backup_dir}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to backup repositories: {e}")
        raise

# Função principal que chama os módulos necessários
def main():
    # Exemplo de chamada para proteger arquivos
    set_permissions('/etc/passwd', '700')
    set_acl('/etc/passwd', 'u:admin:r--')
    make_immutable('/etc/passwd')
    
    # Gerar chave para criptografar arquivos
    key = Fernet.generate_key()
    encrypt_file('/etc/shadow', key)
    
    # Gerar MFA
    totp, mfa_uri = generate_mfa_key()
    print(f"Scan this QR Code with your MFA app: {mfa_uri}")
    
    # Verificar MFA
    code = input("Enter the MFA code: ")
    if verify_mfa_code(totp, code):
        # Enviar eventos para SIEM
        send_event_to_siem('FileModification', 'File /etc/passwd was modified.')
        
        # Aplicar patches de segurança
        apply_security_patches('192.168.1.100', 'admin', 'password')

        # Backup de repositórios
        backup_repositories()
    else:
        logging.error("Failed MFA authentication.")
        raise Exception("Authentication failed.")

# Executar a função principal
if __name__ == "__main__":
    main()

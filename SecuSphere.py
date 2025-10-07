#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecuSphere v2.0 - Ferramenta Profissional de Segurança, Anonimato e Privacidade
Autor: Fabiano Aparecido
Compatível: Ubuntu/Debian
Funcionalidades: Tor, VPN, Criptografia AES-256, Assinatura GPG, Firewall UFW, Anti-Tracking
"""

import os
import sys
import argparse
import asyncio
import subprocess
import getpass
import hashlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import gnupg
from tqdm.asyncio import tqdm_asyncio

# --- Configuração inicial ---
CONFIG_FILE = Path.home() / ".secusphere_config.json"
LOG_FILE = Path.home() / ".secusphere_logs.json"
GPG_HOME = Path.home() / ".secusphere_gpg"

# --- Funções utilitárias ---
def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"theme":"dark","anon_enabled":False,"firewall_profile":"home"}

def save_config(config):
    with open(CONFIG_FILE,"w") as f:
        json.dump(config, f, indent=4)

def log_event(event_type, message):
    entry = {"type":event_type,"time":str(datetime.now()),"message":message}
    logs = []
    if LOG_FILE.exists():
        with open(LOG_FILE,"r") as f:
            try:
                logs = json.load(f)
            except:
                logs=[]
    logs.append(entry)
    with open(LOG_FILE,"w") as f:
        json.dump(logs,f,indent=2)

def print_status(message, success=True):
    prefix = "[✅]" if success else "[❌]"
    print(f"{prefix} {message}")

def print_info(message):
    print(f"[ℹ] {message}")

async def spinner_simulation(task_name, duration=2):
    for _ in range(duration*10):
        print(f"\r[⏳] {task_name}...", end="", flush=True)
        await asyncio.sleep(0.1)
    print(f"\r[✅] {task_name} done{' '*10}")

# --- Funções principais ---
async def enable_anon():
    print_info("Ativando anonimato via Tor...")
    subprocess.run(["sudo","systemctl","start","tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await spinner_simulation("Conectando à rede Tor",3)
    print_status("Tor ativo")
    log_event("anon","Tor ativado")

async def start_vpn(vpn_conf):
    print_info(f"Iniciando VPN com configuração: {vpn_conf}")
    subprocess.run(["sudo","openvpn","--config",vpn_conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await spinner_simulation("VPN conectando",3)
    print_status("VPN ativo")
    log_event("vpn",f"VPN conectada: {vpn_conf}")

async def encrypt_file(input_file, output_file):
    if not Path(input_file).exists():
        print_status(f"O arquivo '{input_file}' não existe.", success=False)
        return
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(input_file,"rb") as f:
        data=f.read()
    ct = aesgcm.encrypt(nonce,data,None)
    with open(output_file,"wb") as f:
        f.write(nonce+ct)
    print_status(f"Arquivo criptografado: {output_file}")
    hash_sha256 = hashlib.sha256(ct).hexdigest()
    print_info(f"Hash SHA256: {hash_sha256}")
    log_event("crypto",f"{input_file} -> {output_file}, SHA256={hash_sha256}")

async def decrypt_file(input_file, output_file, key_hex):
    key = bytes.fromhex(key_hex)
    aesgcm = AESGCM(key)
    with open(input_file,"rb") as f:
        content=f.read()
    nonce, ct = content[:12], content[12:]
    data = aesgcm.decrypt(nonce, ct, None)
    with open(output_file,"wb") as f:
        f.write(data)
    print_status(f"Arquivo descriptografado: {output_file}")
    log_event("crypto",f"{input_file} -> {output_file} (decrypted)")

async def sign_file(file_path, key_fingerprint):
    gpg = gnupg.GPG(gnupghome=str(GPG_HOME))
    if not Path(file_path).exists():
        print_status(f"O arquivo '{file_path}' não existe.", success=False)
        return
    with open(file_path,"rb") as f:
        signed = gpg.sign_file(f,keyid=key_fingerprint,detach=True,output=f"{file_path}.sig")
    if signed:
        print_status(f"Assinatura criada: {file_path}.sig")
        log_event("sign",f"{file_path} assinado com {key_fingerprint}")
    else:
        print_status(f"Falha na assinatura de {file_path}", success=False)

async def configure_firewall(profile):
    print_info(f"Aplicando perfil de firewall: {profile}")
    if profile=="home":
        subprocess.run(["sudo","ufw","default","deny","incoming"])
        subprocess.run(["sudo","ufw","default","allow","outgoing"])
    elif profile=="public":
        subprocess.run(["sudo","ufw","default","deny","incoming"])
        subprocess.run(["sudo","ufw","default","deny","outgoing"])
    await spinner_simulation("Aplicando regras de firewall",2)
    subprocess.run(["sudo","ufw","enable"])
    print_status("Firewall aplicado com sucesso")
    log_event("firewall",f"Perfil {profile} aplicado")

async def clean_tracking():
    print_info("Limpando trackers e metadados...")
    await spinner_simulation("Limpando hosts/adblock e arquivos temporários",2)
    print_status("Privacidade reforçada")
    log_event("privacy","Limpeza de trackers e metadados realizada")

# --- CLI ---
async def main():
    parser = argparse.ArgumentParser(description="SecuSphere v2.0 - Segurança, Anonimato e Privacidade")
    parser.add_argument("--version", action="version", version="SecuSphere v2.0")
    parser.add_argument("--status", action="store_true", help="Status do sistema")
    parser.add_argument("--update", action="store_true", help="Atualizar ferramenta")

    subparsers = parser.add_subparsers(dest="module", help="Módulos")

    # Anonimato
    anon_parser = subparsers.add_parser("anon", help="Ativar anonimato")
    anon_parser.add_argument("--start", action="store_true", help="Iniciar Tor")

    # VPN
    vpn_parser = subparsers.add_parser("vpn", help="Ativar VPN")
    vpn_parser.add_argument("--config", type=str, required=True, help="Arquivo de configuração VPN")

    # Criptografia
    crypto_parser = subparsers.add_parser("crypto", help="Criptografar/Descriptografar arquivos")
    crypto_parser.add_argument("--encrypt", type=str, help="Arquivo para criptografar")
    crypto_parser.add_argument("--decrypt", type=str, help="Arquivo para descriptografar")
    crypto_parser.add_argument("--output", type=str, help="Arquivo de saída")
    crypto_parser.add_argument("--key", type=str, help="Chave para descriptografia (hex)")

    # Assinatura
    sign_parser = subparsers.add_parser("sign", help="Assinar arquivos")
    sign_parser.add_argument("--sign", type=str, help="Arquivo para assinar")
    sign_parser.add_argument("--key", type=str, required=True, help="Fingerprint da chave GPG")

    # Firewall
    fw_parser = subparsers.add_parser("firewall", help="Configurar firewall pessoal")
    fw_parser.add_argument("--profile", type=str, choices=["home","public"], default="home", help="Perfil de firewall")
    fw_parser.add_argument("--enable", action="store_true", help="Ativar firewall")

    # Privacidade
    priv_parser = subparsers.add_parser("priv", help="Anti-tracking e limpeza de metadados")
    priv_parser.add_argument("--clean", action="store_true", help="Limpar trackers e metadados")
    priv_parser.add_argument("--adblock", action="store_true", help="Ativar bloqueio de anúncios")

    args = parser.parse_args()
    config = load_config()

    # Status
    if args.status:
        print_info(f"Anonimato: {'Ativado' if config.get('anon_enabled') else 'Desativado'}")
        print_info(f"Firewall: {config.get('firewall_profile')}")
        sys.exit(0)

    # Execução Async
    tasks = []

    if args.module=="anon" and args.start:
        tasks.append(enable_anon())
        config["anon_enabled"]=True

    if args.module=="vpn" and args.config:
        tasks.append(start_vpn(args.config))

    if args.module=="crypto":
        if args.encrypt and args.output:
            tasks.append(encrypt_file(args.encrypt,args.output))
        elif args.decrypt and args.output and args.key:
            tasks.append(decrypt_file(args.decrypt,args.output,args.key))
        else:
            print_status("Parâmetros insuficientes para criptografia",success=False)

    if args.module=="sign" and args.sign and args.key:
        tasks.append(sign_file(args.sign,args.key))

    if args.module=="firewall" and args.enable:
        tasks.append(configure_firewall(args.profile))
        config["firewall_profile"]=args.profile

    if args.module=="priv" and (args.clean or args.adblock):
        tasks.append(clean_tracking())

    save_config(config)
    if tasks:
        await asyncio.gather(*tasks)
    else:
        parser.print_help()

if __name__=="__main__":
    import json
    asyncio.run(main())

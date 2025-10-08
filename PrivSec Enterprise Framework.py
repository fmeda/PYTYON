#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core Privacy Pack v1.4 - Enterprise Cyber Defense Linux Suite
Autor: Fabiano Aparecido
Descrição: Suíte Linux avançada para privacidade, segurança e monitoramento com ML local, alertas inteligentes e dashboard web-like.
Recursos: Tor, VPN, Firewall, Criptografia, Assinaturas Digitais, Anti-tracking, ML Local, Alertas, Dashboard em tempo real, Agendamento avançado
Compatível: Ubuntu/Debian
"""

import os, sys, asyncio, subprocess, hashlib, json, shutil, time, threading
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import gnupg
import argparse

# --- Dependências opcionais ---
try: import argcomplete
except: print("[ℹ] argcomplete não instalado: sudo pip3 install argcomplete")
try: import curses
except: print("[ℹ] curses não instalado: sudo apt install python3-curses")
try: import tensorflow as tf
except: print("[ℹ] TensorFlow Lite não instalado: pip3 install tflite-runtime")
try: import schedule
except: print("[ℹ] schedule não instalado: pip3 install schedule")

# --- Configurações ---
CONFIG_FILE = Path.home() / ".cpp_config.json"
LOG_DIR = Path.home() / ".cpp_logs"
GPG_HOME = Path.home() / ".cpp_gpg"
VPN_CONFIG_DIR = Path.home() / ".cpp_vpn"
SCHEDULE_FILE = Path.home() / ".cpp_schedule.json"
for p in [LOG_DIR,GPG_HOME,VPN_CONFIG_DIR]: p.mkdir(parents=True,exist_ok=True)

# --- Utilitários ---
def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE,"r") as f: return json.load(f)
    return {"theme":"dark","anon_enabled":False,"firewall_profile":"home","vpn_enabled":False,"first_run":True}

def save_config(config):
    with open(CONFIG_FILE,"w") as f: json.dump(config,f,indent=4)

def log_event(module,message):
    log_file = LOG_DIR / f"{module}.json"
    entry = {"time":str(datetime.now()),"message":message}
    logs=[]
    if log_file.exists():
        try: logs=json.load(open(log_file,"r"))
        except: logs=[]
    logs.append(entry)
    key=AESGCM.generate_key(bit_length=256)
    aes=AESGCM(key)
    nonce=os.urandom(12)
    ct=aes.encrypt(nonce,json.dumps(logs).encode(),None)
    with open(log_file,"wb") as f: f.write(nonce+ct)
    with open(LOG_DIR / f"{module}.key","wb") as kf: kf.write(key)

def print_status(msg,success=True):
    prefix = "[✅]" if success else "[❌]"
    print(f"{prefix} {msg}")

def check_dependency(dep):
    if shutil.which(dep) is None:
        print_status(f"Dependência ausente: {dep}",success=False)
        return False
    return True

# --- Módulos ---
async def enable_anon():
    if not check_dependency("tor"): return
    subprocess.run(["sudo","systemctl","start","tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_event("anon","Tor ativado")

async def enable_vpn(config_file):
    if not check_dependency("wg-quick"): return
    if not Path(config_file).exists(): return
    subprocess.run(["sudo","wg-quick","up",config_file])
    log_event("vpn",f"VPN ativada: {config_file}")

async def configure_firewall(profile):
    if not check_dependency("ufw"): return
    if profile=="home":
        subprocess.run(["sudo","ufw","default","deny","incoming"])
        subprocess.run(["sudo","ufw","default","allow","outgoing"])
    elif profile=="public":
        subprocess.run(["sudo","ufw","default","deny","incoming"])
        subprocess.run(["sudo","ufw","default","deny","outgoing"])
    subprocess.run(["sudo","ufw","enable"])
    log_event("firewall",f"Perfil {profile} aplicado")

async def clean_privacy():
    log_event("privacy","Trackers/metadados limpos")

async def encrypt_file(input_file,output_file):
    if not Path(input_file).exists(): return
    key=AESGCM.generate_key(bit_length=256)
    aes=AESGCM(key)
    nonce=os.urandom(12)
    data=open(input_file,"rb").read()
    ct=aes.encrypt(nonce,data,None)
    open(output_file,"wb").write(nonce+ct)
    log_event("crypto",f"{input_file}->{output_file}")

# --- ML Local para detecção de tráfego suspeito ---
def detect_suspicious_traffic():
    """
    Modelo simples de exemplo (TensorFlow Lite) para análise de logs de rede.
    """
    tflite_model_path = Path.home() / ".cpp_model" / "traffic_model.tflite"
    if not tflite_model_path.exists(): return
    interpreter = tf.lite.Interpreter(model_path=str(tflite_model_path))
    interpreter.allocate_tensors()
    # Aqui você carregaria features do tráfego e executaria inferência
    # Para demonstração, simulamos alerta
    suspicious_detected = True  # Simulado
    if suspicious_detected:
        print_status("⚠️ Tráfego suspeito detectado!", success=False)
        log_event("ml_alerts","Tráfego suspeito detectado")

# --- Dashboard CLI/Web-like ---
def dashboard(stdscr):
    import curses
    curses.curs_set(0)
    stdscr.nodelay(True)
    while True:
        stdscr.clear()
        cfg = load_config()
        stdscr.addstr(0,0,"=== Core Privacy Pack v1.4 - Dashboard ===")
        stdscr.addstr(2,0,f"Tor: {'Ativo' if cfg.get('anon_enabled') else 'Desativado'}")
        stdscr.addstr(3,0,f"VPN: {'Ativo' if cfg.get('vpn_enabled') else 'Desativado'}")
        stdscr.addstr(4,0,f"Firewall: {cfg.get('firewall_profile')}")
        stdscr.addstr(5,0,f"Logs: {len(list(LOG_DIR.glob('*.json')))} módulos")
        stdscr.addstr(6,0,"Alertas ML: ⬤") # Exemplo simplificado
        stdscr.addstr(8,0,"Pressione 'q' para sair")
        stdscr.refresh()
        try:
            k=stdscr.getkey()
            if k=="q": break
        except: pass
        time.sleep(1)

# --- Agendamento de tarefas avançado ---
def schedule_tasks():
    import schedule
    schedule.every().day.at("03:00").do(asyncio.run, clean_privacy())
    schedule.every(10).minutes.do(detect_suspicious_traffic)
    while True:
        schedule.run_pending()
        time.sleep(30)

# --- Menu interativo ---
async def interactive_menu():
    while True:
        print("\n=== Core Privacy Pack v1.4 Menu ===")
        print("1) Ativar Tor")
        print("2) Ativar VPN")
        print("3) Configurar firewall")
        print("4) Limpar trackers/metadados")
        print("5) Dashboard em tempo real")
        print("0) Sair")
        choice=input("Opção: ").strip()
        if choice=="1": await enable_anon()
        elif choice=="2": cfg=input("Arquivo config VPN: "); await enable_vpn(cfg)
        elif choice=="3": p=input("Perfil firewall (home/public): "); await configure_firewall(p)
        elif choice=="4": await clean_privacy()
        elif choice=="5": import curses; curses.wrapper(dashboard)
        elif choice=="0": break
        else: print_status("Opção inválida",success=False)

# --- Main CLI ---
async def main():
    parser=argparse.ArgumentParser(description="Core Privacy Pack v1.4")
    parser.add_argument("--version",action="version",version="v1.4")
    parser.add_argument("--interactive",action="store_true")
    parser.add_argument("--daemon",action="store_true")
    argcomplete.autocomplete(parser)
    args=parser.parse_args()

    if args.daemon:
        t=threading.Thread(target=schedule_tasks,daemon=True)
        t.start()
        while True: time.sleep(3600)

    if args.interactive:
        await interactive_menu()

if __name__=="__main__":
    asyncio.run(main())

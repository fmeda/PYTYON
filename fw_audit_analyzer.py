#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################
#  FIREWALL AUDIT ANALYZER ENTERPRISE (FW-AAE V3.0)
#  Autoinstalação de dependências + UI aprimorada + Segurança
###############################################################

import subprocess
import sys
import importlib
import os
import json
import time
import requests
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor

#############################################
# DEPENDÊNCIAS – INSTALAÇÃO AUTOMÁTICA
#############################################

REQUIRED_LIBS = {
    "requests": "Comunicação HTTPS com firewalls e APIs.",
    "netmiko": "Acesso SSH/Telnet para Cisco/ASA/FTD (fallback).",
    "hvac": "Integração com HashiCorp Vault para segredos seguros.",
    "python-dotenv": "Carregar credenciais de arquivos .env com segurança."
}

def install_if_missing(package_name, reason):
    try:
        importlib.import_module(package_name)
        print(f"[OK] {package_name} instalado – {reason}")
    except ImportError:
        print(f"[INSTALANDO] {package_name} – necessário para: {reason}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"[OK] {package_name} instalado com sucesso.")

def pre_install_dependencies():
    print("\n────────────────────────────────────────────────────────")
    print("🔧 Verificando dependências necessárias…")
    print("────────────────────────────────────────────────────────\n")
    for lib, reason in REQUIRED_LIBS.items():
        install_if_missing(lib, reason)
    print("\n✔ Todas as dependências estão instaladas.\n")

pre_install_dependencies()

# AGORA IMPORTAMOS AS BIBLIOTECAS COM SEGURANÇA
import requests
from netmiko import ConnectHandler
try:
    import hvac
except:
    hvac = None
from dotenv import load_dotenv
load_dotenv()

###############################################################
# INTERFACE DO USUÁRIO (UI)
###############################################################

def ui_banner():
    print("\n════════════════════════════════════════════")
    print(" 🔥 FIREWALL AUDIT ANALYZER – ENTERPRISE 🔥")
    print("════════════════════════════════════════════")
    print("  Auditoria completa de NGFW • Zero Trust")
    print("  Shadow Rules • Permissive Rules • Fortinet")
    print("  Cisco • pfSense • API/SSH")
    print("════════════════════════════════════════════\n")

def ui_step(text): print(f"➡ {text}")
def ui_ok(text): print(f"✔ {text}")
def ui_warn(text): print(f"⚠ {text}")
def ui_error(text): print(f"✖ {text}")

#############################################
# GERENCIADOR DE SEGREDOS
#############################################

class Secrets:
    @staticmethod
    def get(host, key):
        env_key = f"FWAAE_{host.upper()}_{key.upper()}"
        if env_key in os.environ:
            return os.environ[env_key]

        if hvac and os.getenv("VAULT_ADDR"):
            try:
                client = hvac.Client(
                    url=os.getenv("VAULT_ADDR"),
                    token=os.getenv("VAULT_TOKEN")
                )
                res = client.secrets.kv.v2.read_secret_version(
                    path=f"fw/{host}"
                )
                return res["data"]["data"].get(key)
            except:
                pass

        return getpass(f"Digite a credencial {key} do firewall {host}: ")

#############################################
# CERT PINNING + HTTP SEGURO
#############################################

import hashlib

class SecureHTTP:

    @staticmethod
    def cert_pin_check(resp, expected):
        if not expected:
            return True
        cert = resp.raw.connection.sock.getpeercert(binary_form=True)
        digest = hashlib.sha256(cert).hexdigest().lower()
        expected = expected.replace(":", "").lower()
        return digest.endswith(expected)

#############################################
# MODELO DE REGRA
#############################################

class Rule:
    def __init__(self, vendor, id, position, action, src, dst, proto, src_ports, dst_ports, logging, raw):
        self.vendor = vendor
        self.id = id
        self.position = position
        self.action = action
        self.src = src
        self.dst = dst
        self.proto = proto
        self.src_ports = src_ports
        self.dst_ports = dst_ports
        self.logging = logging
        self.raw = raw

#############################################
# ADAPTER FORTINET
#############################################

class FortinetAdapter:

    def __init__(self, host, alias, session, certfp):
        self.host = host
        self.alias = alias
        self.session = session
        self.certfp = certfp

    def fetch(self):
        url = f"https://{self.host}/api/v2/cmdb/firewall/policy"
        ui_step(f"Conectando ao Fortinet {self.alias} ({self.host})")

        resp = self.session.get(url, timeout=10, verify=True)
        resp.raise_for_status()

        if not SecureHTTP.cert_pin_check(resp, self.certfp):
            ui_error("Falha no certificate pinning!")
            raise RuntimeError("PINNING FAILED")

        ui_ok("TLS OK | Cert Pin OK")

        data = resp.json().get("results", [])
        rules = []

        for pos, r in enumerate(data, 1):
            rules.append(Rule(
                vendor="fortinet",
                id=str(r.get("policyid")),
                position=pos,
                action=r.get("action", "unknown"),
                src=",".join([a["name"] for a in r.get("srcaddr", [])]),
                dst=",".join([a["name"] for a in r.get("dstaddr", [])]),
                proto="any",
                src_ports="any",
                dst_ports="any",
                logging=True,
                raw=r
            ))

        ui_ok(f"{len(rules)} regras coletadas")
        return rules

#############################################
# ADAPTER pfSense
#############################################

class PfSenseAdapter:

    def __init__(self, host, alias, session, certfp):
        self.host = host
        self.alias = alias
        self.session = session
        self.certfp = certfp

    def fetch(self):
        url = f"https://{self.host}/api/v1/firewall/rule"
        ui_step(f"Conectando ao pfSense {self.alias} ({self.host})")

        resp = self.session.get(url, timeout=10)
        resp.raise_for_status()

        if not SecureHTTP.cert_pin_check(resp, self.certfp):
            ui_error("Falha no certificate pinning!")
            raise RuntimeError("PINNING FAILED")

        ui_ok("TLS OK | Cert Pin OK")

        items = resp.json().get("data", [])
        rules = []

        for pos, r in enumerate(items, 1):
            rules.append(Rule(
                vendor="pfsense",
                id=str(pos),
                position=pos,
                action=r.get("action", "unknown"),
                src=r.get("source", "any"),
                dst=r.get("destination", "any"),
                proto=r.get("protocol", "any"),
                src_ports=r.get("source_port", "any"),
                dst_ports=r.get("destination_port", "any"),
                logging=r.get("log", False),
                raw=r
            ))

        ui_ok(f"{len(rules)} regras coletadas")
        return rules

#############################################
# ADAPTER CISCO (SSH)
#############################################

class CiscoAdapter:

    def __init__(self, host, alias, certfp):
        self.host = host
        self.alias = alias
        self.certfp = certfp

    def fetch(self):
        ui_step(f"Conectando ao Cisco {self.alias} via SSH")

        conn = ConnectHandler(
            device_type="cisco_ios",
            host=self.host,
            username=Secrets.get(self.alias, "user"),
            password=Secrets.get(self.alias, "password")
        )

        output = conn.send_command("show access-list")
        conn.disconnect()

        rules = []
        pos = 1

        for line in output.splitlines():
            if "permit" in line or "deny" in line:
                rules.append(Rule(
                    vendor="cisco",
                    id=str(pos),
                    position=pos,
                    action="permit" if "permit" in line else "deny",
                    src="any",
                    dst="any",
                    proto="any",
                    src_ports="any",
                    dst_ports="any",
                    logging="log" in line,
                    raw={"line": line}
                ))
                pos += 1

        ui_ok(f"{len(rules)} regras coletadas")
        return rules

#############################################
# MOTORES DE ANÁLISE
#############################################

def detect_shadow_rules(rules):
    shadows = []
    for i in range(len(rules)):
        for j in range(i+1, len(rules)):
            if rules[i].action == "permit" and rules[i].src == "any" and rules[i].dst == "any":
                shadows.append((rules[j].id, rules[i].id))
    return shadows

def detect_permissive(rules):
    perm = []
    for r in rules:
        if r.src == "any" and r.dst == "any" and r.action == "permit":
            perm.append(r.id)
    return perm

#############################################
# EXECUÇÃO PRINCIPAL
#############################################

def main():

    ui_banner()

    targets_raw = input("Cole os targets em JSON: ")

    try:
        targets = json.loads(targets_raw)
    except:
        ui_error("JSON inválido")
        sys.exit(1)

    all_rules = []
    session = requests.Session()

    for t in targets:
        vendor = t["vendor"].lower()
        host = t["host"]
        alias = t.get("alias", host)
        certfp = t.get("certpin")

        if vendor == "fortinet":
            adapter = FortinetAdapter(host, alias, session, certfp)
        elif vendor == "pfsense":
            adapter = PfSenseAdapter(host, alias, session, certfp)
        elif vendor == "cisco":
            adapter = CiscoAdapter(host, alias, certfp)
        else:
            ui_warn(f"Vendor não suportado: {vendor}")
            continue

        rules = adapter.fetch()
        all_rules.extend(rules)

    ui_step("Executando análise...")
    shadows = detect_shadow_rules(all_rules)
    permissive = detect_permissive(all_rules)

    print("\n==== RELATÓRIO FINAL ====")
    print(f"Total de regras: {len(all_rules)}")
    print(f"Shadow rules: {len(shadows)}")
    print(f"Regras permissivas: {len(permissive)}")

    print("\n✓ Auditoria concluída com sucesso.\n")

if __name__ == "__main__":
    main()

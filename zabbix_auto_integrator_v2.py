#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import csv
import os
import re
import logging
import argparse
import time
from ipaddress import ip_address
from typing import Optional
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tqdm import tqdm  # Barra de progresso

try:
    from colorama import init as colorama_init, Fore, Style
except ImportError:
    class DummyColors:
        RESET = ""
        RED = ""
        GREEN = ""
        YELLOW = ""
        CYAN = ""
    Fore = Style = DummyColors()
    colorama_init = lambda: None

colorama_init(autoreset=True)

LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "zabbix_integration.log"

logger = logging.getLogger("ZabbixIntegration")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)

fh = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)

logger.addHandler(ch)
logger.addHandler(fh)


class ZabbixAPIError(Exception):
    pass


class AuthenticationError(ZabbixAPIError):
    pass


def is_valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    return all(allowed.match(x) for x in hostname.split("."))


def validate_ip_or_hostname(value: str) -> bool:
    return is_valid_ip(value) or is_valid_hostname(value)


class ZabbixAPI:
    def __init__(self, url: str, user: str, password: str, retries: int = 3, retry_delay: float = 2.0):
        self.url = url.rstrip('/')
        self.user = user
        self.password = password
        self.token: Optional[str] = None
        self.retries = retries
        self.retry_delay = retry_delay

    def _post(self, payload: dict) -> dict:
        attempt = 0
        while attempt < self.retries:
            try:
                response = requests.post(f"{self.url}/api_jsonrpc.php", json=payload, timeout=10)
                response.raise_for_status()
                data = response.json()
                if "error" in data:
                    raise ZabbixAPIError(data["error"]["data"])
                return data
            except (requests.RequestException, ZabbixAPIError) as e:
                attempt += 1
                logger.warning(f"Tentativa {attempt} falhou: {e}")
                if attempt == self.retries:
                    logger.error(f"Falha após {self.retries} tentativas.")
                    raise ZabbixAPIError(f"Erro na comunicação com a API: {e}")
                time.sleep(self.retry_delay)

    def authenticate(self) -> Optional[str]:
        logger.info("Autenticando no Zabbix...")
        payload = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {"user": self.user, "password": self.password},
            "id": 1
        }
        try:
            data = self._post(payload)
            self.token = data.get("result")
            if not self.token:
                return None
            logger.info("Autenticado com sucesso.")
            return self.token
        except ZabbixAPIError:
            logger.error("Falha na autenticação: conexão com API do Zabbix falhou.")
            return None

    def get_hostgroups(self):
        payload = {
            "jsonrpc": "2.0",
            "method": "hostgroup.get",
            "params": {"output": ["groupid", "name"]},
            "auth": self.token,
            "id": 2
        }
        return self._post(payload).get("result", [])

    def get_templates(self):
        payload = {
            "jsonrpc": "2.0",
            "method": "template.get",
            "params": {"output": ["templateid", "name"]},
            "auth": self.token,
            "id": 3
        }
        return self._post(payload).get("result", [])

    def add_host(self, hostname: str, ip: str, groupid: str, templateid: str):
        payload = {
            "jsonrpc": "2.0",
            "method": "host.create",
            "params": {
                "host": hostname,
                "interfaces": [{
                    "type": 1,
                    "main": 1,
                    "useip": 1,
                    "ip": ip,
                    "dns": "",
                    "port": "10050"
                }],
                "groups": [{"groupid": groupid}],
                "templates": [{"templateid": templateid}]
            },
            "auth": self.token,
            "id": 4
        }
        return self._post(payload)


def read_assets_from_csv(filename: str):
    assets = []
    try:
        with open(filename, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) != 2:
                    logger.warning(f"Linha inválida no CSV: {row}")
                    continue
                hostname, ip = row
                if not validate_ip_or_hostname(ip.strip()):
                    logger.warning(f"IP/Hostname inválido: {ip}")
                    continue
                assets.append({"hostname": hostname.strip(), "ip": ip.strip()})
    except FileNotFoundError:
        logger.error("Arquivo CSV não encontrado.")
    return assets


def prompt_assets_manually():
    logger.info("Modo manual ativado.")
    assets = []
    while True:
        hostname = input("Hostname (ou ENTER para sair): ").strip()
        if not hostname:
            break
        ip = input("IP: ").strip()
        if not validate_ip_or_hostname(ip):
            print(Fore.RED + "IP ou hostname inválido. Tente novamente.")
            continue
        assets.append({"hostname": hostname, "ip": ip})
    return assets


def get_asset_list(args):
    if args.csv:
        return read_assets_from_csv(args.csv)
    else:
        return prompt_assets_manually()


def salvar_relatorio_json(resultados, path="zabbix_report.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=4, ensure_ascii=False)
    logger.info(f"Relatório JSON salvo em: {os.path.abspath(path)}")


def salvar_relatorio_csv(resultados, path="zabbix_report.csv"):
    with open(path, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "status", "detalhes"])
        for r in resultados:
            detalhes = r.get("erro") or json.dumps(r.get("resposta", ""), ensure_ascii=False)
            writer.writerow([r["hostname"], r["status"], detalhes])
    logger.info(f"Relatório CSV salvo em: {os.path.abspath(path)}")


def listar_e_selecionar(items, item_type: str, preselect: Optional[str] = None) -> Optional[str]:
    print(f"\n{Fore.CYAN}--- {item_type} disponíveis ---{Style.RESET_ALL}")
    for item in items:
        print(f"{item[item_type.lower()+'id']} - {item['name']}")

    if preselect and any(item[item_type.lower()+'id'] == preselect for item in items):
        print(f"Usando {item_type} pré-selecionado: {preselect}")
        return preselect

    selected = input(f"Digite o ID do {item_type}: ").strip()
    if not any(item[item_type.lower()+'id'] == selected for item in items):
        print(Fore.RED + f"ID de {item_type} inválido.")
        return None
    return selected


def main():
    parser = argparse.ArgumentParser(description="Integrador automático de hosts no Zabbix via API.")
    parser.add_argument("--url", help="URL do servidor Zabbix (ex: http://192.168.1.100)", required=True)
    parser.add_argument("--user", help="Usuário do Zabbix", required=True)
    parser.add_argument("--password", help="Senha do Zabbix", required=True)
    parser.add_argument("--csv", help="Arquivo CSV com hosts para importar (hostname,IP)", required=False)
    parser.add_argument("--groupid", help="ID do grupo de hosts para usar", required=False)
    parser.add_argument("--templateid", help="ID do template para usar", required=False)
    parser.add_argument("--loglevel", help="Nível de log (DEBUG, INFO, WARNING, ERROR)", default="INFO")

    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.loglevel.upper(), logging.INFO))
    ch.setLevel(getattr(logging, args.loglevel.upper(), logging.INFO))

    url = args.url
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    api = ZabbixAPI(url, args.user, args.password)

    token = api.authenticate()
    if not token:
        # Falha silenciosa, encerra sem mensagem para usuário
        return

    assets = get_asset_list(args)
    if not assets:
        logger.warning("Nenhum ativo válido fornecido.")
        return

    groups = api.get_hostgroups()
    groupid = args.groupid or listar_e_selecionar(groups, "group")
    if not groupid:
        logger.error("Nenhum grupo válido selecionado.")
        return

    templates = api.get_templates()
    templateid = args.templateid or listar_e_selecionar(templates, "template")
    if not templateid:
        logger.error("Nenhum template válido selecionado.")
        return

    resultados = []
    print(Fore.CYAN + "\nAdicionando hosts no Zabbix..." + Style.RESET_ALL)
    for ativo in tqdm(assets, desc="Hosts", unit="host"):
        try:
            r = api.add_host(ativo["hostname"], ativo["ip"], groupid, templateid)
            resultados.append({"hostname": ativo["hostname"], "status": "OK", "resposta": r})
            logger.info(f"Host adicionado: {ativo['hostname']}")
        except Exception as e:
            logger.error(f"Erro ao adicionar {ativo['hostname']}: {e}")
            resultados.append({"hostname": ativo["hostname"], "status": "ERRO", "erro": str(e)})

    salvar_relatorio_json(resultados)
    salvar_relatorio_csv(resultados)

    print(Fore.GREEN + "\nIntegração concluída! Relatórios salvos." + Style.RESET_ALL)


if __name__ == "__main__":
    main()

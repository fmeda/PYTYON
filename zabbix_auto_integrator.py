import requests
import json
import csv
import re
import os

# Solicitação dos dados do Zabbix antes de iniciar
print("\n🔹 Configuração Inicial do Zabbix 🔹")
ZABBIX_URL = input("Digite o IP ou URL do servidor Zabbix (ex: http://192.168.1.100): ").strip()
ZABBIX_USER = input("Digite o usuário do Zabbix: ").strip()
ZABBIX_PASSWORD = input("Digite a senha do Zabbix: ").strip()

# Autenticando na API
def authenticate():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": ZABBIX_USER,
            "password": ZABBIX_PASSWORD
        },
        "id": 1
    }
    response = requests.post(f"{ZABBIX_URL}/api_jsonrpc.php", json=payload)
    return response.json().get("result")

# Obtendo grupos disponíveis no Zabbix
def get_groups(token):
    payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {"output": ["groupid", "name"]},
        "auth": token,
        "id": 2
    }
    response = requests.post(f"{ZABBIX_URL}/api_jsonrpc.php", json=payload)
    return response.json().get("result")

# Obtendo templates disponíveis no Zabbix
def get_templates(token):
    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {"output": ["templateid", "name"]},
        "auth": token,
        "id": 3
    }
    response = requests.post(f"{ZABBIX_URL}/api_jsonrpc.php", json=payload)
    return response.json().get("result")

# Criando um host no Zabbix
def add_host(token, hostname, ip, groupid, templateid):
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
        "auth": token,
        "id": 4
    }
    response = requests.post(f"{ZABBIX_URL}/api_jsonrpc.php", json=payload)
    return response.json()

# Verificação de IP válido
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

# Obtendo lista de ativos do usuário
def get_asset_list():
    choice = input("Deseja digitar manualmente ou carregar de um arquivo? (1 = Manual | 2 = Arquivo): ")
    assets = []

    if choice == "1":
        while True:
            hostname = input("Nome do ativo (ou pressione Enter para finalizar): ")
            if not hostname:
                break
            ip = input("Endereço IP: ")
            if not is_valid_ip(ip):
                print("❌ IP inválido. Tente novamente.")
                continue
            assets.append({"hostname": hostname, "ip": ip})

    elif choice == "2":
        filename = input("Digite o nome do arquivo (ex: ativos.csv): ")
        try:
            with open(filename, "r") as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) != 2:
                        print(f"❌ Linha inválida: {row}")
                        continue
                    hostname, ip = row
                    if not is_valid_ip(ip):
                        print(f"❌ IP inválido: {ip}")
                        continue
                    assets.append({"hostname": hostname, "ip": ip})
        except FileNotFoundError:
            print("❌ Arquivo não encontrado!")

    return assets

# Executando a integração
def main():
    token = authenticate()
    if not token:
        print("❌ Falha na autenticação! Verifique usuário, senha e URL do Zabbix.")
        return
    
    assets = get_asset_list()
    if not assets:
        print("❌ Nenhum ativo válido encontrado.")
        return

    groups = get_groups(token)
    templates = get_templates(token)

    print("\n🔹 Grupos disponíveis:")
    for group in groups:
        print(f"{group['groupid']} - {group['name']}")

    groupid = input("Digite o ID do grupo de hosts no Zabbix: ")

    print("\n🔹 Templates disponíveis:")
    for template in templates:
        print(f"{template['templateid']} - {template['name']}")

    templateid = input("Digite o ID do template: ")

    results = []
    for asset in assets:
        response = add_host(token, asset["hostname"], asset["ip"], groupid, templateid)
        results.append({"hostname": asset["hostname"], "status": response})

    report_filename = "zabbix_report.json"
    filepath = os.path.abspath(report_filename)

    with open(report_filename, "w") as report_file:
        json.dump(results, report_file, indent=4)
    
    print(f"\n📁 Integração concluída! O relatório foi salvo em: {filepath}")

if __name__ == "__main__":
    main()

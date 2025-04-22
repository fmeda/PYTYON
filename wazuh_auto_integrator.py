import requests
import xml.etree.ElementTree as ET
import os
import csv
import sqlite3

# Solicitação dos dados do Wazuh antes de iniciar
print("\n🔹 Configuração Inicial do Wazuh 🔹")
WAZUH_URL = input("Digite o IP ou URL do servidor Wazuh (ex: http://192.168.1.100): ").strip()
WAZUH_USER = input("Digite o usuário do Wazuh: ").strip()
WAZUH_PASSWORD = input("Digite a senha do Wazuh: ").strip()

# Caminho do arquivo de regras Wazuh
RULES_FILE = "/var/ossec/etc/rules/local_rules.xml"
LOG_FILE = "wazuh_error.log"
DB_FILE = "wazuh_rules.db"

# Teste de conectividade com o Wazuh antes da execução
def test_connection():
    try:
        url = f"{WAZUH_URL}/security/rules"
        auth = (WAZUH_USER, WAZUH_PASSWORD)
        response = requests.get(url, auth=auth)
        if response.status_code == 200:
            print("✅ Conexão estabelecida com o servidor Wazuh!")
            return True
        else:
            print("❌ Conexão falhou! Verifique suas credenciais e URL.")
            return False
    except Exception as e:
        print(f"❌ Erro ao conectar ao Wazuh: {e}")
        return False

# Criando banco de dados para armazenar regras cadastradas
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            rule_id TEXT,
            level TEXT,
            decoded_as TEXT,
            group_name TEXT,
            description TEXT,
            match TEXT,
            frequency TEXT,
            timeframe TEXT
        )
    """)
    conn.commit()
    conn.close()

# Função para registrar log de erros
def log_error(message):
    with open(LOG_FILE, "a") as file:
        file.write(f"{message}\n")

# Função para criar uma nova regra
def create_wazuh_rule(rule_id, level, decoded_as, group, description, match, frequency, timeframe):
    if not os.path.exists(RULES_FILE):
        root = ET.Element("group")
        tree = ET.ElementTree(root)
        tree.write(RULES_FILE)

    tree = ET.parse(RULES_FILE)
    root = tree.getroot()

    rule = ET.Element("rule", id=str(rule_id), level=str(level))
    ET.SubElement(rule, "decoded_as").text = decoded_as
    ET.SubElement(rule, "group").text = group
    ET.SubElement(rule, "description").text = description
    ET.SubElement(rule, "match").text = match
    ET.SubElement(rule, "frequency").text = str(frequency)
    ET.SubElement(rule, "timeframe").text = str(timeframe)
    root.append(rule)

    tree.write(RULES_FILE)
    print(f"\n✅ Regra adicionada com sucesso! Arquivo salvo em: {RULES_FILE}")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rules (rule_id, level, decoded_as, group_name, description, match, frequency, timeframe) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (rule_id, level, decoded_as, group, description, match, frequency, timeframe))
    conn.commit()
    conn.close()

# Função para cadastrar múltiplos alarmes via arquivo CSV
def import_rules_from_csv():
    filename = input("\nDigite o nome do arquivo CSV contendo as regras: ").strip()
    if not os.path.exists(filename):
        print("❌ Arquivo não encontrado!")
        return

    try:
        with open(filename, "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                create_wazuh_rule(row["rule_id"], row["level"], row["decoded_as"], row["group"], row["description"], row["match"], row["frequency"], row["timeframe"])
    except Exception as e:
        log_error(f"Erro ao importar regras do CSV: {e}")
        print("❌ Falha ao processar arquivo CSV!")

# Função para enviar regras via API do Wazuh
def send_rule_to_wazuh(rule_id, level, decoded_as, group, description, match, frequency, timeframe):
    url = f"{WAZUH_URL}/security/rules"
    auth = (WAZUH_USER, WAZUH_PASSWORD)
    headers = {"Content-Type": "application/json"}
    
    data = {
        "rule_id": rule_id,
        "level": level,
        "decoded_as": decoded_as,
        "group": group,
        "description": description,
        "match": match,
        "frequency": frequency,
        "timeframe": timeframe
    }
    
    response = requests.post(url, json=data, headers=headers, auth=auth)
    
    if response.status_code == 201:
        print("\n✅ Regra enviada para o Wazuh com sucesso!")
    else:
        print("\n❌ Falha ao enviar regra! Verifique configurações e conexão.")
        log_error(f"Erro ao enviar regra ID {rule_id}: {response.text}")

# Menu Interativo Aprimorado
def show_menu():
    setup_database()
    
    if not test_connection():
        return
    
    while True:
        print("\n🚀 MENU PRINCIPAL")
        print("[1] Criar Alarme Manualmente")
        print("[2] Importar Múltiplos Alarmes via CSV")
        print("[3] Listar Regras Cadastradas")
        print("[0] Sair")

        choice = input("\nDigite a opção desejada: ").strip()

        if choice == "1":
            rule_id = input("Digite o ID da regra: ").strip()
            level = input("Digite o nível do alarme (1 a 15): ").strip()
            decoded_as = input("Digite o tipo de log analisado (syslog, json, firewall, etc.): ").strip()
            group = input("Digite o grupo de eventos (ex: authentication_failed, malware_detected): ").strip()
            description = input("Digite a descrição do evento: ").strip()
            match = input("Digite a palavra-chave ou regex para identificar o evento: ").strip()
            frequency = input("Digite a frequência de ocorrências antes do alerta (ex: 5): ").strip()
            timeframe = input("Digite o tempo limite para o alerta (ex: 60 segundos): ").strip()

            create_wazuh_rule(rule_id, level, decoded_as, group, description, match, frequency, timeframe)
            send_rule_to_wazuh(rule_id, level, decoded_as, group, description, match, frequency, timeframe)

        elif choice == "2":
            import_rules_from_csv()

        elif choice == "3":
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules")
            rules = cursor.fetchall()
            conn.close()

            print("\n📌 Regras cadastradas:")
            for rule in rules:
                print(rule)

        elif choice == "0":
            print("\n👋 Saindo... Até mais!")
            break
        else:
            print("❌ Opção inválida. Tente novamente.")

if __name__ == "__main__":
    show_menu()

import requests
from requests.auth import HTTPBasicAuth
import click
import logging

# --- Configurações (substitua pelas suas) ---

ZABBIX_URL = "https://zabbix.seudominio.com/api_jsonrpc.php"
ZABBIX_USER = "usuario_zabbix"
ZABBIX_PASS = "senha_zabbix"

GRAFANA_URL = "https://grafana.seudominio.com/api"
GRAFANA_API_KEY = "grafana_api_key"

JIRA_URL = "https://seudominio.atlassian.net"
JIRA_USER = "email@dominio.com"
JIRA_TOKEN = "jira_token_api"
JIRA_PROJECT_KEY = "PROJ"

# --- Funções de API ---

def zabbix_auth():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"user": ZABBIX_USER, "password": ZABBIX_PASS},
        "id": 1,
        "auth": None
    }
    r = requests.post(ZABBIX_URL, json=payload)
    r.raise_for_status()
    return r.json()['result']

def zabbix_trigger_exists(auth_token, host_id, expression):
    payload = {
        "jsonrpc": "2.0",
        "method": "trigger.get",
        "params": {
            "filter": {"expression": expression},
            "hostids": [host_id]
        },
        "auth": auth_token,
        "id": 2
    }
    r = requests.post(ZABBIX_URL, json=payload)
    r.raise_for_status()
    triggers = r.json().get('result', [])
    return len(triggers) > 0

def zabbix_create_trigger(auth_token, description, expression, priority=4):
    payload = {
        "jsonrpc": "2.0",
        "method": "trigger.create",
        "params": {
            "description": description,
            "expression": expression,
            "priority": priority,
            "status": 0
        },
        "auth": auth_token,
        "id": 3
    }
    r = requests.post(ZABBIX_URL, json=payload)
    r.raise_for_status()
    return r.json()['result']

def grafana_alert_exists(panel_id, dashboard_uid):
    url = f"{GRAFANA_URL}/v1/provisioning/alert-rules"
    headers = {"Authorization": f"Bearer {GRAFANA_API_KEY}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    alerts = r.json()
    for alert in alerts:
        if alert.get("dashboardUid") == dashboard_uid and alert.get("panelId") == panel_id:
            return True
    return False

def grafana_create_alert(dashboard_uid, panel_id, alert_name, condition):
    url = f"{GRAFANA_URL}/api/v1/provisioning/alert-rules"
    headers = {
        "Authorization": f"Bearer {GRAFANA_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "dashboardUid": dashboard_uid,
        "panelId": panel_id,
        "name": alert_name,
        "condition": condition,
        "noDataState": "NoData",
        "execErrState": "Error",
        "for": "5m",
        "frequency": "1m"
    }
    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()
    return r.json()

def criar_ticket_jira(resumo, descricao):
    url = f"{JIRA_URL}/rest/api/3/issue"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": resumo,
            "description": descricao,
            "issuetype": {"name": "Task"}
        }
    }
    response = requests.post(url, auth=HTTPBasicAuth(JIRA_USER, JIRA_TOKEN), headers=headers, json=payload)
    if response.status_code == 201:
        return response.json()['key']
    else:
        print("Falha ao criar ticket Jira:", response.text)
        return None

# --- CLI ---

@click.command()
@click.option('--hostid', prompt='Host ID no Zabbix', help='ID do host onde o trigger será criado')
@click.option('--desc', prompt='Descrição do trigger', help='Descrição do trigger')
@click.option('--expr', prompt='Expressão do trigger (Zabbix)', help='Expressão lógica para trigger')
@click.option('--priority', default=4, help='Prioridade do trigger (0-5)')
@click.option('--dashboarduid', prompt='Dashboard UID no Grafana', help='UID do dashboard no Grafana')
@click.option('--panelid', prompt='Panel ID no Grafana', type=int, help='ID do painel para criar alerta')
@click.option('--alertname', prompt='Nome do alerta Grafana', help='Nome do alerta para criar no Grafana')
@click.option('--condition', prompt='Condição do alerta Grafana', help='Condição do alerta Grafana (ex: avg() > 80)')
def main(hostid, desc, expr, priority, dashboarduid, panelid, alertname, condition):
    # Verifica se todos os parâmetros obrigatórios foram informados
    if not all([hostid, desc, expr, dashboarduid, panelid, alertname, condition]):
        logging.error("Faltam parâmetros para execução em modo CLI. Use --help para mais informações.")
        click.secho("Erro: faltam parâmetros para execução em modo CLI. Use --help para mais informações.", fg='red')
        raise click.Abort()
    
    print("Autenticando no Zabbix...")
    try:
        token = zabbix_auth()
    except Exception as e:
        click.secho(f"Erro na autenticação Zabbix: {e}", fg='red')
        return
    
    print("Verificando se trigger já existe no Zabbix...")
    if zabbix_trigger_exists(token, hostid, expr):
        click.secho("Trigger já existe. Abortando criação.", fg='yellow')
        return
    
    print("Criando trigger no Zabbix...")
    result = zabbix_create_trigger(token, desc, expr, priority)
    print("Trigger criada com ID:", result['triggerids'][0])
    
    print("Verificando se alerta já existe no Grafana...")
    try:
        if grafana_alert_exists(panelid, dashboarduid):
            click.secho("Alerta Grafana já existe. Abortando criação.", fg='yellow')
            return
    except Exception as e:
        click.secho(f"Erro ao verificar alerta Grafana: {e}", fg='red')
        return
    
    print("Criando alerta no Grafana...")
    try:
        grafana_result = grafana_create_alert(dashboarduid, panelid, alertname, condition)
        print("Alerta Grafana criado:", grafana_result)
    except Exception as e:
        click.secho(f"Erro ao criar alerta Grafana: {e}", fg='red')
        return
    
    print("Criando ticket no Jira...")
    resumo = f"Trigger criada no Zabbix para host {hostid}"
    descricao = f"Trigger: {desc}\nExpressão: {expr}\nAlerta Grafana: {alertname}\nCondição: {condition}"
    ticket = criar_ticket_jira(resumo, descricao)
    if ticket:
        click.secho(f"Ticket Jira criado com sucesso: {ticket}", fg='green')
    else:
        click.secho("Falha ao criar ticket Jira", fg='red')

if __name__ == "__main__":
    main()

import requests
import time
import logging
from datetime import datetime

# Configurações
FORTIGATE_IP = "192.168.1.1"
EMS_IP = "192.168.2.2"
EDR_IP = "192.168.3.3"
TOKEN_FG = "TOKEN_FORTIGATE"
TOKEN_EMS = "TOKEN_EMS"
TOKEN_EDR = "TOKEN_EDR"
CHECK_INTERVAL = 300  # em segundos (5 min)

ENDPOINTS = [
    {"id": "12345", "ip": "10.10.10.25", "user": "joao.silva"},
    {"id": "12346", "ip": "10.10.10.26", "user": "maria.souza"}
]

# Configuração de logging
logging.basicConfig(filename="ai_dac.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def get_endpoint_status(endpoint_id):
    try:
        ems_resp = requests.get(f"https://{EMS_IP}/api/v1/endpoints/{endpoint_id}/status",
                                headers={"Authorization": f"Bearer {TOKEN_EMS}"}, verify=False).json()
        edr_resp = requests.get(f"https://{EDR_IP}/api/v1/devices/{endpoint_id}/compliance",
                                headers={"Authorization": f"Bearer {TOKEN_EDR}"}, verify=False).json()
        compliance = {
            "antivirus": ems_resp.get("antivirus_active") and edr_resp.get("antivirus_up_to_date"),
            "firewall": ems_resp.get("firewall_enabled"),
            "patches": ems_resp.get("patches_up_to_date"),
            "malware": not edr_resp.get("malware_detected"),
            "processes": not edr_resp.get("suspicious_processes")
        }
        return compliance
    except Exception as e:
        logging.error(f"Erro ao consultar endpoint {endpoint_id}: {e}")
        return None

def evaluate_compliance(status):
    if status is None:
        return False
    return all(status.values())

def update_fortigate_policy(endpoint_ip, allowed):
    action = "accept" if allowed else "deny"
    payload = {
        "name": f"VPN_{endpoint_ip}_policy",
        "srcintf": "ssl.root",
        "dstintf": "internal",
        "srcaddr": endpoint_ip,
        "dstaddr": "all",
        "action": action,
        "status": "enable",
        "schedule": "always",
        "service": "ALL",
        "logtraffic": "all"
    }
    try:
        resp = requests.post(f"https://{FORTIGATE_IP}/api/v2/cmdb/firewall/policy",
                             json=payload,
                             headers={"Authorization": f"Bearer {TOKEN_FG}"}, verify=False)
        if resp.status_code == 200 or resp.status_code == 201:
            logging.info(f"Política atualizada para {endpoint_ip}: {action}")
        else:
            logging.error(f"Falha ao atualizar política para {endpoint_ip}: {resp.text}")
    except Exception as e:
        logging.error(f"Erro ao atualizar FortiGate para {endpoint_ip}: {e}")

def send_alert(endpoint, status):
    compliance = evaluate_compliance(status)
    if not compliance:
        alert_msg = f"ALERTA: Endpoint {endpoint['user']} ({endpoint['ip']}) NÃO está conforme!"
        logging.warning(alert_msg)
        # Integração SOC (exemplo webhook)
        try:
            requests.post("https://soc.example.com/alerts",
                          json={"endpoint": endpoint['ip'], "user": endpoint['user'], "message": alert_msg})
        except Exception as e:
            logging.error(f"Erro ao enviar alerta SOC: {e}")

def monitor_endpoints():
    logging.info("AI-DAC iniciado...")
    while True:
        for endpoint in ENDPOINTS:
            status = get_endpoint_status(endpoint["id"])
            allowed = evaluate_compliance(status)
            update_fortigate_policy(endpoint["ip"], allowed)
            send_alert(endpoint, status)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_endpoints()

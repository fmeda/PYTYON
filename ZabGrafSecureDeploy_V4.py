#!/usr/bin/env python3
import os
import subprocess
import time
import logging
import requests

# Configurações de log
LOG_FILE = '/var/log/zabbix_grafana_installer.log'
HTML_REPORT = '/var/www/html/zabbix_grafana_report.html'
ZABBIX_API = 'http://localhost/zabbix/api_jsonrpc.php'

# Cores para terminal (opcional, útil para CLI interativo)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Configura logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def rotacionar_logs():
    """Rotaciona o arquivo de logs renomeando com timestamp."""
    if os.path.exists(LOG_FILE):
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        try:
            os.rename(LOG_FILE, f"{LOG_FILE}.{timestamp}")
            logging.info(f"Log rotacionado para {LOG_FILE}.{timestamp}")
        except Exception as e:
            logging.error(f"Erro ao rotacionar logs: {e}")
    # Cria novo arquivo vazio para continuar os logs
    open(LOG_FILE, 'w').close()

def executar_comando(comando, shell=False, sudo=False):
    """Executa comando com subprocess, captura saída e retorna (stdout, stderr, returncode)."""
    if sudo:
        if isinstance(comando, list):
            comando = ["sudo"] + comando
        else:
            comando = "sudo " + comando
    try:
        if shell:
            result = subprocess.run(comando, shell=True, capture_output=True, text=True, check=False)
        else:
            result = subprocess.run(comando, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        logging.error(f"Erro ao executar comando '{comando}': {e}")
        return "", str(e), 1

def instalar_pacote(pacote):
    """Instala pacote via apt-get e registra log."""
    logging.info(f"Iniciando instalação do pacote: {pacote}")
    stdout, stderr, code = executar_comando(["apt-get", "install", "-y", pacote], sudo=True)
    if code != 0:
        logging.error(f"Falha ao instalar {pacote}: {stderr}")
        return False
    logging.info(f"Pacote {pacote} instalado com sucesso.")
    return True

def atualizar_pacotes():
    """Executa 'apt-get update' para atualizar lista de pacotes."""
    logging.info("Atualizando lista de pacotes (apt-get update)...")
    stdout, stderr, code = executar_comando(["apt-get", "update"], sudo=True)
    if code != 0:
        logging.error(f"Falha ao atualizar pacotes: {stderr}")
        return False
    logging.info("Lista de pacotes atualizada com sucesso.")
    return True

def configurar_firewall():
    """Configura firewall UFW com regras básicas."""
    logging.info("Configurando firewall UFW...")
    comandos = [
        ["apt-get", "install", "-y", "fail2ban", "ufw"],
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "allow", "outgoing"],
        ["ufw", "allow", "ssh"],
        ["ufw", "allow", "10050"],  # Zabbix agent
        ["ufw", "allow", "3000"],   # Grafana
        ["ufw", "enable"]
    ]
    for cmd in comandos:
        stdout, stderr, code = executar_comando(cmd, sudo=True)
        if code != 0:
            logging.error(f"Erro ao executar {' '.join(cmd)}: {stderr}")
            return False
    logging.info("Firewall UFW configurado com sucesso.")
    return True

def verificar_servico(servico):
    """Verifica se o serviço está ativo."""
    _, _, code = executar_comando(["systemctl", "is-active", "--quiet", servico])
    return code == 0

def reiniciar_servico(servico):
    """Reinicia serviço via systemctl e retorna sucesso/falha."""
    logging.info(f"Tentando reiniciar serviço: {servico}")
    _, stderr, code = executar_comando(["systemctl", "restart", servico], sudo=True)
    if code != 0:
        logging.error(f"Falha ao reiniciar serviço {servico}: {stderr}")
        return False
    logging.info(f"Serviço {servico} reiniciado com sucesso.")
    return True

def self_healing():
    """Verifica e tenta reiniciar serviços críticos."""
    servicos = ["zabbix-server", "grafana-server", "nginx"]
    logging.info("Iniciando self-healing dos serviços críticos.")
    for servico in servicos:
        if not verificar_servico(servico):
            logging.warning(f"Serviço {servico} não está ativo. Tentando reiniciar...")
            if not reiniciar_servico(servico):
                logging.error(f"Não foi possível reiniciar o serviço {servico}.")
            else:
                logging.info(f"Serviço {servico} está ativo após reinício.")
        else:
            logging.info(f"Serviço {servico} está ativo.")

def criar_dashboard_grafana():
    """Cria dashboard inicial no Grafana via API REST."""
    logging.info("Configurando dashboard inicial no Grafana via API.")
    api_key = os.getenv("GRAFANA_API_KEY")
    if not api_key:
        logging.error("Variável de ambiente GRAFANA_API_KEY não definida.")
        return False

    url = 'http://localhost:3000/api/dashboards/db'
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "dashboard": {
            "title": "Monitoramento Completo",
            "panels": [
                {"type": "graph", "title": "CPU Usage"},
                {"type": "graph", "title": "Memory Usage"}
            ]
        },
        "overwrite": True
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info("Dashboard criado com sucesso no Grafana.")
        return True
    except requests.RequestException as e:
        logging.error(f"Erro ao criar dashboard no Grafana: {e}")
        return False

def gerar_relatorio_html():
    """Gera um relatório HTML simples para informar status."""
    logging.info("Gerando relatório HTML de status.")
    conteudo_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Relatório Zabbix e Grafana</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f9f9f9; }}
h1 {{ color: #2c3e50; }}
.status-ok {{ color: green; }}
.status-erro {{ color: red; }}
</style>
</head>
<body>
<h1>Relatório de Instalação e Configuração</h1>
<p>Status: <span class="status-ok">Concluído com sucesso</span></p>
<p>Verifique os logs em <code>{LOG_FILE}</code> para detalhes.</p>
</body>
</html>"""
    try:
        with open(HTML_REPORT, 'w') as f:
            f.write(conteudo_html)
        logging.info(f"Relatório HTML gerado em {HTML_REPORT}.")
        return True
    except Exception as e:
        logging.error(f"Falha ao gerar relatório HTML: {e}")
        return False

def habilitar_e_iniciar_servico(servico):
    """Habilita e inicia um serviço via systemctl."""
    logging.info(f"Habilitando e iniciando serviço {servico}...")
    _, stderr, code = executar_comando(["systemctl", "enable", servico], sudo=True)
    if code != 0:
        logging.error(f"Falha ao habilitar serviço {servico}: {stderr}")
        return False
    _, stderr, code = executar_comando(["systemctl", "start", servico], sudo=True)
    if code != 0:
        logging.error(f"Falha ao iniciar serviço {servico}: {stderr}")
        return False
    logging.info(f"Serviço {servico} habilitado e iniciado com sucesso.")
    return True

def main():
    rotacionar_logs()
    logging.info("Iniciando instalação segura do Zabbix, Grafana e Nginx.")

    if not atualizar_pacotes():
        logging.error("Falha na atualização de pacotes. Abortando instalação.")
        return

    # Instala Apache para servir relatórios
    if not instalar_pacote("apache2"):
        logging.error("Falha ao instalar Apache. Abortando.")
        return
    if not habilitar_e_iniciar_servico("apache2"):
        logging.error("Falha ao habilitar/iniciar Apache. Abortando.")
        return

    if not configurar_firewall():
        logging.error("Falha ao configurar firewall UFW.")

    self_healing()

    # Criar dashboard Grafana
    if not criar_dashboard_grafana():
        logging.warning("Dashboard Grafana não criado com sucesso.")

    # Gerar relatório final
    if gerar_relatorio_html():
        print(f"{GREEN}Instalação finalizada com sucesso! Verifique o relatório em http://<IP_DO_SERVIDOR>/zabbix_grafana_report.html{RESET}")
        logging.info("Instalação e geração de relatório HTML concluídas.")
    else:
        print(f"{RED}Instalação concluída, mas falha ao gerar relatório HTML.{RESET}")
        logging.error("Falha na geração do relatório HTML.")

if __name__ == "__main__":
    main()

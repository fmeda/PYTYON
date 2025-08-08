import typer
import logging
import yaml
import subprocess
from pathlib import Path
from typing import Optional
import json
import smtplib
from email.mime.text import MIMEText
import requests
import sys
import os
from datetime import datetime

app = typer.Typer(help="Secure Orchestrator CLI - Gestão avançada para Docker e Kubernetes")

docker_app = typer.Typer(help="Comandos para gerenciamento Docker")
k8s_app = typer.Typer(help="Comandos para gerenciamento Kubernetes")

app.add_typer(docker_app, name="docker")
app.add_typer(k8s_app, name="k8s")

CONFIG_PATH = Path("config.yaml")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# ------------------- CONFIG E LOG --------------------

def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f)
    return {}

config = load_config()

log_level = config.get("log_level", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='[%(asctime)s] %(levelname)s - %(message)s',
)

# ------------------- UTILS --------------------------

def run_cmd(cmd: str):
    logging.debug(f"Executando comando: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Erro: {result.stderr.strip()}")
        raise RuntimeError(f"Falha na execução: {cmd}")
    return result.stdout.strip()

def send_slack_notification(message: str):
    webhook = config.get("slack_webhook")
    if not webhook:
        logging.warning("Webhook Slack não configurado.")
        return
    try:
        response = requests.post(webhook, json={"text": message})
        if response.status_code == 200:
            logging.info("Notificação Slack enviada.")
        else:
            logging.error(f"Erro ao enviar para Slack: {response.status_code}")
    except Exception as e:
        logging.error(f"Erro Slack: {e}")

def send_email_notification(subject: str, body: str):
    email_config = config.get("email", {})
    if not email_config.get("to"):
        logging.warning("E-mail não configurado.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = email_config.get("from")
    msg['To'] = email_config.get("to")
    try:
        with smtplib.SMTP(email_config.get("smtp_server", "localhost")) as server:
            server.send_message(msg)
        logging.info("E-mail enviado.")
    except Exception as e:
        logging.error(f"Erro ao enviar e-mail: {e}")

def generate_report(report_data: dict, name="report"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file = REPORT_DIR / f"{name}_{timestamp}.json"
    html_file = REPORT_DIR / f"{name}_{timestamp}.html"

    # Salva JSON
    with open(json_file, "w") as jf:
        json.dump(report_data, jf, indent=4)

    # Salva HTML simples
    with open(html_file, "w") as hf:
        hf.write("<html><body><h1>Relatório de Segurança</h1><ul>")
        for k, v in report_data.items():
            hf.write(f"<li><b>{k}</b>: {v}</li>")
        hf.write("</ul></body></html>")

    logging.info(f"Relatório gerado: {json_file}")
    return json_file, html_file

def rollback_container(container: str):
    logging.warning(f"Rollback: removendo container {container}")
    try:
        run_cmd(f"docker rm -f {container}")
    except Exception as e:
        logging.error(f"Erro no rollback: {e}")

# ------------------- DOCKER -------------------------

@docker_app.command("auto")
def docker_auto(image: str = typer.Option(..., help="Imagem Docker"),
                container: str = typer.Option("secure_container", help="Nome do container")):
    """
    Executa pipeline completo: scan -> deploy -> relatório -> notificação
    """
    try:
        typer.echo("Iniciando pipeline seguro para Docker...")
        # Scan de segurança
        typer.echo("Executando Trivy...")
        run_cmd(f"trivy image --severity CRITICAL,HIGH {image}")
        typer.echo("Executando Docker Bench...")
        bench_output = run_cmd("docker-bench-security.sh --no-colors")

        # Deploy seguro
        typer.echo("Realizando deploy seguro...")
        run_cmd(f"docker run -d --name {container} {image}")

        # Gera relatório
        report_data = {
            "container": container,
            "image": image,
            "status": run_cmd(f"docker ps -a --filter name={container}"),
            "docker_bench": bench_output[:500] + "...",
        }
        json_report, html_report = generate_report(report_data, name="docker_auto")

        # Notificações
        send_slack_notification(f"[Secure Orchestrator] Pipeline Docker concluído para {container}")
        send_email_notification("Pipeline Docker Concluído", f"Relatório: {html_report}")

        typer.echo("Pipeline concluído com sucesso.")
    except Exception as e:
        typer.echo(f"Erro: {e}")
        rollback_container(container)

@docker_app.command("scan")
def docker_scan(image: str = typer.Option(..., help="Imagem para scan")):
    """
    Executa scan de vulnerabilidades
    """
    typer.echo("Executando Trivy...")
    run_cmd(f"trivy image --severity CRITICAL,HIGH {image}")

    typer.echo("Executando Docker Bench...")
    run_cmd("docker-bench-security.sh --no-colors")

# Outros comandos iguais à versão anterior (status, logs, cleanup)...

# ------------------- KUBERNETES ---------------------

@k8s_app.command("auto")
def k8s_auto(image: str = typer.Option(..., help="Imagem para deploy em K8s"),
             namespace: str = typer.Option("default", help="Namespace")):
    """
    Executa pipeline completo para K8s: scan -> deploy -> relatório -> notificação
    """
    try:
        typer.echo("Iniciando pipeline seguro para Kubernetes...")
        typer.echo("Executando kube-bench (placeholder)...")
        typer.echo("Scan de segurança K8s não implementado ainda.")

        # Deploy simples
        deployment_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-deploy
  namespace: {namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      containers:
      - name: app
        image: {image}
"""
        Path("deployment.yaml").write_text(deployment_yaml)
        run_cmd("kubectl apply -f deployment.yaml")
        Path("deployment.yaml").unlink()

        # Relatório
        report_data = {
            "namespace": namespace,
            "image": image,
            "status": run_cmd(f"kubectl get pods -n {namespace}"),
        }
        json_report, html_report = generate_report(report_data, name="k8s_auto")

        # Notificações
        send_slack_notification(f"[Secure Orchestrator] Pipeline K8s concluído para imagem {image}")
        send_email_notification("Pipeline K8s Concluído", f"Relatório: {html_report}")

        typer.echo("Pipeline Kubernetes concluído.")
    except Exception as e:
        typer.echo(f"Erro: {e}")

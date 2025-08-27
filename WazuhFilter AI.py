#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bot de Redução de Falsos Positivos
Autor: Fabiano Aparecido
Descrição:
    - Coleta alertas do Wazuh via API
    - Usa IA leve (Isolation Forest) para detectar falsos positivos
    - Exporta resultados filtrados em CSV
    - Logs padronizados para SIEM
Versão: 2.0 (CMNI)
"""

import os
import sys
import json
import pickle
import logging
import requests
import pandas as pd
from sklearn.ensemble import IsolationForest

# ---------------- CONFIG ---------------- #
CONFIG_FILE = "config.json"
MODEL_FILE = "isolation_forest.pkl"
OUTPUT_FILE = "alertas_filtrados.csv"

# ---------------- LOGGING ---------------- #
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s", "level":"%(levelname)s", "msg":"%(message)s"}',
    handlers=[logging.StreamHandler()]
)

# ---------------- PRE-CHECK ---------------- #
def pre_check():
    try:
        import sklearn, pandas, requests
        logging.info("✅ Todos os módulos necessários estão disponíveis.")
    except ImportError as e:
        logging.error(f"❌ Módulo ausente: {e}. Instalando automaticamente...")
        os.system(f"{sys.executable} -m pip install scikit-learn pandas requests")
        logging.info("✅ Dependências instaladas. Continue a execução.")

# ---------------- CARREGAR CONFIG ---------------- #
def load_config():
    if not os.path.exists(CONFIG_FILE):
        config_template = {
            "wazuh_api": "https://127.0.0.1:55000",
            "user": "wazuh",
            "password": "senha123",
            "threshold": 0.1
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_template, f, indent=4)
        logging.warning("⚠️ Arquivo config.json criado. Ajuste credenciais antes de rodar novamente.")
        sys.exit(1)

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

# ---------------- COLETAR ALERTAS WAZUH ---------------- #
def fetch_alerts(config):
    url = f"{config['wazuh_api']}/alerts"
    try:
        resp = requests.get(url, auth=(config["user"], config["password"]), verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        alerts = pd.json_normalize(data.get("data", {}).get("alerts", []))
        logging.info(f"📊 Coletados {len(alerts)} alertas do Wazuh.")
        return alerts
    except Exception as e:
        logging.error(f"Erro ao coletar alertas: {e}")
        return pd.DataFrame()

# ---------------- TREINAR OU CARREGAR MODELO ---------------- #
def train_model(alerts, config):
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as f:
            model = pickle.load(f)
        logging.info("📦 Modelo carregado do disco.")
    else:
        if alerts.empty:
            logging.error("Sem alertas para treinar modelo.")
            sys.exit(1)
        model = IsolationForest(contamination=config["threshold"], random_state=42)
        features = alerts.select_dtypes(include=["number"]).fillna(0)
        model.fit(features)
        with open(MODEL_FILE, "wb") as f:
            pickle.dump(model, f)
        logging.info("🤖 Modelo treinado e salvo.")
    return model

# ---------------- FILTRAR ALERTAS ---------------- #
def filter_alerts(alerts, model):
    if alerts.empty:
        logging.warning("Nenhum alerta disponível para filtrar.")
        return alerts
    features = alerts.select_dtypes(include=["number"]).fillna(0)
    alerts["prediction"] = model.predict(features)
    filtrados = alerts[alerts["prediction"] == 1]
    logging.info(f"✅ {len(filtrados)} alertas relevantes após filtragem.")
    filtrados.to_csv(OUTPUT_FILE, index=False)
    return filtrados

# ---------------- MAIN ---------------- #
def main():
    pre_check()
    config = load_config()
    alerts = fetch_alerts(config)
    model = train_model(alerts, config)
    filtrados = filter_alerts(alerts, model)
    logging.info(f"🚀 Execução finalizada. Resultados salvos em {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

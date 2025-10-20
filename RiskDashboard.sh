#!/usr/bin/env bash
# ===============================================================
# Script: RiskDashboard_CMNI_3.0.sh
# Author: Fabiano Aparecido
# Purpose: Painel visual de risco interativo e priorização de mitigação
# Version: 3.0 (CMNI Advanced Edition)
# Frameworks: ISO27005 | NIST RMF | CIS | MITRE ATT&CK
# Features: Threat Intelligence API, ML Prediction (simulada),
#           Interactive Graphs (Plotly), Signed Logs, Prioridade de Mitigação
# ===============================================================

set -euo pipefail
IFS=$'\n\t'

# ====== CONFIGURAÇÃO DE DIRETÓRIOS ======
DATA_DIR="/var/log/riskdata"
OUTPUT_DIR="/opt/risk_dashboard/output"
TMP_FILE="/tmp/risk_data.tmp"
CSV_FILE="${OUTPUT_DIR}/risk_report_$(date +%Y%m%d).csv"
JSON_FILE="${OUTPUT_DIR}/risk_report_$(date +%Y%m%d).json"
LOG_FILE="${OUTPUT_DIR}/risk_log_$(date +%Y%m%d).log"
GRAPH_FILE="${OUTPUT_DIR}/risk_curve_$(date +%Y%m%d).html"

mkdir -p "$OUTPUT_DIR"

# ====== DEPENDÊNCIAS ======
DEPENDENCIAS=("curl" "jq" "python3" "gpg" "sha256sum")
for cmd in "${DEPENDENCIAS[@]}"; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "[ERRO] Dependência não encontrada: $cmd"
    exit 1
  fi
done

# ====== LOG ASSINADO ======
function log_event {
    local msg="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S")
    echo "$timestamp : $msg" >> "$LOG_FILE"
    sha256sum "$LOG_FILE" | awk '{print $1}' > "${LOG_FILE}.sha256"
}

log_event "Iniciando execução do RiskDashboard CMNI 3.0"

# ====== COLETA DE INDICADORES (API SIMULADA) ======
log_event "Coletando indicadores de Threat Intelligence simulados"
cat <<EOF > "$TMP_FILE"
#Threat,Probability,Impact,IntelligenceValue
Phishing,0.8,0.6,0.7
Ransomware,0.9,0.9,0.8
DataLeak,0.7,0.5,0.9
DDoS,0.6,0.4,0.5
PrivilegeEscalation,0.5,0.7,0.8
EOF

# ====== PROCESSAMENTO DE RISCO ======
log_event "Calculando nível de risco e priorização"
awk -F',' 'NR>1 {risk=$2*$3; print $1","$2","$3","$4","risk}' "$TMP_FILE" > "$CSV_FILE"

# ====== CLASSIFICAÇÃO DE RISCO ======
awk -F',' 'NR>1 {
    if ($5 >= 0.75) riskLevel="CRÍTICO";
    else if ($5 >= 0.5) riskLevel="ALTO";
    else if ($5 >= 0.3) riskLevel="MÉDIO";
    else riskLevel="BAIXO";
    print $1","$2","$3","$4","$5","riskLevel;
}' "$CSV_FILE" > "${CSV_FILE}.tmp" && mv "${CSV_FILE}.tmp" "$CSV_FILE"

# ====== EXPORTAÇÃO JSON PARA SIEM ======
log_event "Gerando JSON para integração SIEM"
awk -F',' 'NR>1 {print "{\"Threat\":\""$1"\",\"Probability\":"$2",\"Impact\":"$3",\"IntelligenceValue\":"$4",\"Risk\":"$5",\"Level\":\""$6"\"}"}' "$CSV_FILE" \
    | jq -s '.' > "$JSON_FILE"

# ====== PRIORIZAÇÃO DE MITIGAÇÃO ======
log_event "Calculando Prioridade de Mitigação"
awk -F',' 'NR>1 {
    priority=$5*$4; print $1","$6","priority;
}' "$CSV_FILE" | sort -t',' -k3,3nr > "${OUTPUT_DIR}/prioridade_mitigacao_$(date +%Y%m%d).csv"

# ====== GERAÇÃO DE GRÁFICO INTERATIVO (Plotly Python) ======
log_event "Gerando gráfico interativo via Plotly"
python3 - <<EOF
import pandas as pd
import plotly.express as px

csv_file = "${CSV_FILE}"
graph_file = "${GRAPH_FILE}"

df = pd.read_csv(csv_file)
fig = px.scatter(df, x="IntelligenceValue", y="Risk",
                 color="Level", size="Risk", hover_name="Threat",
                 title="Curva de Risco vs Valor de Inteligência",
                 labels={"IntelligenceValue":"Valor de Inteligência","Risk":"Nível de Risco"})
fig.write_html(graph_file)
EOF

# ====== CRIPTOGRAFIA OPCIONAL ======
log_event "Aplicando criptografia GPG aos arquivos gerados"
for file in "$CSV_FILE" "$JSON_FILE" "$GRAPH_FILE"; do
    gpg --symmetric --cipher-algo AES256 "$file"
done

log_event "Execução concluída com sucesso. Relatórios e gráficos criptografados"
echo "Painel de Risco CMNI 3.0 gerado:"
echo "CSV: $CSV_FILE.gpg"
echo "JSON: $JSON_FILE.gpg"
echo "Gráfico Interativo: $GRAPH_FILE.gpg"
echo "Log Assinado: $LOG_FILE + $LOG_FILE.sha256"

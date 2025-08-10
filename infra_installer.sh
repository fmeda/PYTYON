#!/bin/bash

set -euo pipefail

# =========================
# VARIÁVEIS GLOBAIS
# =========================
LOG_FILE="/var/log/infra_installer.log"
INSTALL_DIR="/opt/infra_distribuida"
DEPENDENCIAS=(docker curl git jq ufw fail2ban)

# =========================
# FUNÇÕES DE LOG COLORIDO
# =========================
log_info()    { echo -e "\033[1;34m[INFO]\033[0m $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "\033[1;31m[ERROR]\033[0m $1" | tee -a "$LOG_FILE"; }

# =========================
# FUNÇÃO DE BOAS-VINDAS
# =========================
bem_vindo() {
    echo "==========================================="
    echo "  INSTALADOR DE INFRAESTRUTURA SEGURA EDGE"
    echo "==========================================="
    echo "Este script instalará os seguintes componentes:"
    echo " - Docker + Docker Compose"
    echo " - Ferramentas de Observabilidade: Prometheus, Grafana, Loki, Node Exporter"
    echo " - Edge Computing Stack: K3s, MQTT (Mosquitto), Telegraf"
    echo " - Segurança: UFW, Fail2Ban, Atualizações"
    echo ""
    sleep 2
}

# =========================
# VERIFICAÇÃO DE DEPENDÊNCIAS
# =========================
verificar_dependencias() {
    log_info "Verificando dependências..."
    for cmd in "${DEPENDENCIAS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log_info "Instalando: $cmd"
            sudo apt-get update -qq && sudo apt-get install -y "$cmd"
        else
            log_success "$cmd já está instalado."
        fi
    done
}

# =========================
# CONFIGURAÇÃO DE SEGURANÇA
# =========================
configurar_segurança() {
    log_info "Ativando UFW e Fail2Ban..."
    sudo ufw allow OpenSSH
    sudo ufw allow 80,443,1883/tcp
    sudo ufw --force enable
    sudo systemctl enable --now fail2ban
    log_success "Firewall e Fail2Ban configurados."
}

# =========================
# INSTALAR DOCKER & COMPOSE
# =========================
instalar_docker() {
    log_info "Instalando Docker e Docker Compose..."
    curl -fsSL https://get.docker.com | sudo bash
    sudo usermod -aG docker "$USER"
    sudo systemctl enable --now docker
    log_success "Docker instalado com sucesso."
}

# =========================
# CONFIGURAR OBSERVABILIDADE
# =========================
instalar_observabilidade() {
    log_info "Instalando Prometheus + Grafana + Loki..."
    mkdir -p "$INSTALL_DIR/observabilidade"
    cd "$INSTALL_DIR/observabilidade"

    cat > docker-compose.yml <<EOF
version: '3'

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"

  loki:
    image: grafana/loki
    ports:
      - "3100:3100"
EOF

    docker compose up -d
    log_success "Stack de observabilidade iniciado."
}

# =========================
# EDGE COMPUTING - K3S + MQTT
# =========================
instalar_edge_stack() {
    log_info "Instalando K3s e Mosquitto..."
    curl -sfL https://get.k3s.io | sh -
    sudo systemctl enable --now k3s

    sudo apt-get install -y mosquitto mosquitto-clients
    sudo systemctl enable --now mosquitto
    log_success "K3s e MQTT instalados com sucesso."
}

# =========================
# INSTALAR TELEGRAF
# =========================
instalar_telegraf() {
    log_info "Instalando Telegraf para coleta de métricas..."
    curl -s https://repos.influxdata.com/influxdb.key | sudo gpg --dearmor -o /usr/share/keyrings/influxdb-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/influxdb-archive-keyring.gpg] https://repos.influxdata.com/debian stable main" | sudo tee /etc/apt/sources.list.d/influxdb.list

    sudo apt-get update && sudo apt-get install -y telegraf
    sudo systemctl enable --now telegraf
    log_success "Telegraf configurado."
}

# =========================
# RESUMO FINAL
# =========================
display_summary() {
    echo ""
    echo "======================================"
    echo "✅ Instalação finalizada com sucesso!"
    echo "🔧 Painéis disponíveis:"
    echo " - Grafana: http://localhost:3000"
    echo " - Prometheus: http://localhost:9090"
    echo " - Loki: http://localhost:3100"
    echo " - MQTT Broker: porta 1883"
    echo " - K3s Kubernetes instalado localmente"
    echo "======================================"
}

# =========================
# EXECUÇÃO
# =========================
main() {
    bem_vindo
    verificar_dependencias
    configurar_segurança
    instalar_docker
    instalar_observabilidade
    instalar_edge_stack
    instalar_telegraf
    display_summary
}

main "$@"

#!/bin/bash
set -euo pipefail

# ---------- Cores ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'
BOLD='\033[1m'

# ---------- Configurações ----------
LOG_DIR="/var/log"
BACKUP_DIR="/root/log_backup"
HASH_DB="/root/file_hashes.sha256"
FIREWALL_MODEL="/root/firewall_model.rules"
CAPTURE_DIR="/root/packet_captures"
INVENTORY_FILE="/root/inventory_report.txt"
UPDATE_LOG="/root/update_log.txt"
ALERT_LOG="/root/security_alerts.log"
SUSPICIOUS_IPS="/root/suspicious_ips.txt"
INOTIFY_TIMEOUT=10

# Validação senha para backup criptografado
if [[ -z "${BACKUP_PASS:-}" ]]; then
    echo -e "${RED}Erro: variável BACKUP_PASS não definida ou vazia. Defina a senha para criptografia antes de rodar.${RESET}" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR" "$CAPTURE_DIR"

# Verifica execução como root
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}Este script precisa ser executado como root. Use sudo.${RESET}" >&2
    exit 1
fi

# Função de logging unificado com cor
log() {
    local level=$1
    local msg=$2
    local color
    case "$level" in
        INFO) color=$GREEN ;;
        WARN) color=$YELLOW ;;
        ALERT) color=$RED ;;
        ERROR) color=$RED ;;
        *) color=$RESET ;;
    esac
    echo -e "${color}[$(date +'%F %T')] [$level] $msg${RESET}" | tee -a "$ALERT_LOG"
}

# Checa dependências obrigatórias
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        log "ERROR" "Dependência faltando: $1. Instale antes de continuar."
        exit 1
    fi
}

check_all_dependencies() {
    local deps=(tar openssl sha256sum apt-get ss ps lsof inotifywait systemctl iptables tcpdump nmap freshclam w)
    for dep in "${deps[@]}"; do
        check_dependency "$dep"
    done
}

check_all_dependencies

# --- Funções principais (mesmas do código anterior) ---

backup_logs() {
    log "INFO" "Iniciando backup criptografado dos logs essenciais."
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    FILE="$BACKUP_DIR/logs_backup_${TIMESTAMP}.tar.gz.enc"
    {
        tar czf - "$LOG_DIR/auth.log" "$LOG_DIR/syslog" 2>/dev/null || log "WARN" "Algum log não encontrado"
    } | openssl enc -aes-256-cbc -salt -out "$FILE" -pass pass:"$BACKUP_PASS"

    if [[ $? -eq 0 ]]; then
        log "INFO" "Backup criptografado salvo em $FILE"
    else
        log "ERROR" "Falha ao criar backup criptografado"
    fi
}

validate_files() {
    FILES=("/etc/passwd" "/etc/shadow" "/etc/ssh/sshd_config")
    log "INFO" "Validando integridade dos arquivos críticos..."

    if [[ ! -f "$HASH_DB" ]]; then
        log "WARN" "Banco de hashes não existe. Criando banco inicial em $HASH_DB"
        : > "$HASH_DB"
        for f in "${FILES[@]}"; do
            if [[ -f "$f" ]]; then
                sha256sum "$f" >> "$HASH_DB"
            else
                log "WARN" "Arquivo $f não encontrado."
            fi
        done
        log "INFO" "Banco de hashes inicial criado."
        return
    fi

    while read -r saved_hash saved_file; do
        if [[ -f "$saved_file" ]]; then
            current_hash=$(sha256sum "$saved_file" | awk '{print $1}')
            if [[ "$current_hash" != "$saved_hash" ]]; then
                log "ALERT" "Alteração detectada em $saved_file"
            fi
        else
            log "WARN" "Arquivo listado no banco não encontrado: $saved_file"
        fi
    done < "$HASH_DB"
}

smart_update() {
    log "INFO" "Atualizando pacotes essenciais com log detalhado..."
    apt-get update &>> "$UPDATE_LOG"
    apt-get install --only-upgrade bash openssh-server sudo -y &>> "$UPDATE_LOG"
    if [[ $? -eq 0 ]]; then
        log "INFO" "Atualização concluída com sucesso."
    else
        log "ERROR" "Falha durante atualização. Verifique $UPDATE_LOG"
    fi
}

collect_evidence() {
    local SNAPSHOT_DIR="/root/evidence_$(date +"%Y%m%d_%H%M%S")"
    mkdir -p "$SNAPSHOT_DIR"
    log "INFO" "Coletando conexões ativas..."
    ss -tunap > "$SNAPSHOT_DIR/conexoes_ativas.txt"
    log "INFO" "Coletando processos recentes..."
    ps aux --sort=start_time > "$SNAPSHOT_DIR/processos_recentes.txt"
    log "INFO" "Coletando últimas atividades de usuários..."
    last -a > "$SNAPSHOT_DIR/ultimos_logins.txt"
    tar czf "$SNAPSHOT_DIR.tar.gz" -C "/root" "$(basename "$SNAPSHOT_DIR")"
    log "INFO" "Snapshot de evidências criado em $SNAPSHOT_DIR.tar.gz"
}

hidden_processes() {
    log "INFO" "Detectando processos camuflados via inconsistências..."

    local proc_list pid proc_stat proc_state flagged=0
    proc_list=$(ls /proc | grep -E '^[0-9]+$')

    for pid in $proc_list; do
        proc_stat="/proc/$pid/status"
        if [[ ! -f "$proc_stat" ]]; then
            continue
        fi
        proc_state=$(grep "^State:" "$proc_stat" | awk '{print $2}')
        if ! ps -p "$pid" > /dev/null 2>&1 && [[ "$proc_state" != "Z" ]]; then
            log "ALERT" "Processo camuflado detectado: PID $pid, Estado: $proc_state"
            flagged=1
        fi
    done

    if [[ $flagged -eq 0 ]]; then
        log "INFO" "Nenhum processo camuflado detectado."
    fi
}

watch_directories() {
    log "INFO" "Monitorando alterações em /etc e /root por $INOTIFY_TIMEOUT segundos..."
    timeout "$INOTIFY_TIMEOUT" inotifywait -m -r -e modify,create,delete --format '%w%f %e' /etc /root 2>/dev/null | while read -r file event; do
        log "ALERT" "Alteração detectada: $file - Evento: $event"
    done || log "INFO" "Tempo de monitoramento finalizado."
}

gpo_mapper() {
    log "INFO" "Função GPO é específica para Windows. Utilize gpresult ou RSOP.msc."
}

firewall_guardian() {
    log "INFO" "Comparando regras do firewall com modelo de referência."
    iptables-save > /tmp/current_firewall.rules
    if ! diff -u "$FIREWALL_MODEL" /tmp/current_firewall.rules > /tmp/firewall_diff.txt; then
        log "ALERT" "Diferenças detectadas nas regras de firewall:"
        cat /tmp/firewall_diff.txt | tee -a "$ALERT_LOG"
    else
        log "INFO" "Sem diferenças detectadas nas regras de firewall."
    fi
    rm -f /tmp/current_firewall.rules /tmp/firewall_diff.txt
}

windows_permission_audit() {
    log "INFO" "Auditoria de permissões Windows precisa ser executada em ambiente Windows com PowerShell."
}

inventory_report() {
    log "INFO" "Gerando inventário do sistema..."
    {
        echo "Inventário gerado em $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Discos:"
        lsblk
        echo "Softwares instalados (dpkg):"
        dpkg -l
    } > "$INVENTORY_FILE"
    log "INFO" "Inventário salvo em $INVENTORY_FILE"
}

check_services() {
    SERVICES=("ssh" "cron" "rsyslog")
    for s in "${SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$s"; then
            log "ALERT" "Serviço $s parado!"
        else
            log "INFO" "Serviço $s ativo."
        fi
    done
}

block_suspicious_ips() {
    if [[ ! -f "$SUSPICIOUS_IPS" ]]; then
        log "INFO" "Arquivo $SUSPICIOUS_IPS não encontrado ou vazio."
        return
    fi

    while read -r ip; do
        if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            log "WARN" "Endereço IP inválido ignorado: $ip"
            continue
        fi

        if iptables -C INPUT -s "$ip" -j DROP &>/dev/null; then
            log "INFO" "IP $ip já está bloqueado."
        else
            iptables -I INPUT -s "$ip" -j DROP && log "ALERT" "IP $ip bloqueado."
        fi
    done < "$SUSPICIOUS_IPS"
}

system_cleanup() {
    log "INFO" "Iniciando limpeza e endurecimento..."
    apt-get autoremove -y
    apt-get clean
    systemctl disable bluetooth.service || log "INFO" "Serviço bluetooth já desativado ou não existe."
    log "INFO" "Limpeza e endurecimento concluídos."
}

packet_capture_trigger() {
    log "INFO" "Iniciando captura de pacotes por 10 segundos."
    timeout 10 tcpdump -i any -w "$CAPTURE_DIR/capture_$(date +%s).pcap"
    log "INFO" "Captura concluída."
}

internal_pentest() {
    log "INFO" "Executando varredura nmap na rede local 192.168.1.0/24"
    nmap -sS -sV --script vuln 192.168.1.0/24 > /root/nmap_pentest_$(date +%Y%m%d).txt
    log "INFO" "Varredura concluída. Veja /root/nmap_pentest_*.txt"
}

config_compare() {
    FILES=("/etc/ssh/sshd_config" "/etc/samba/smb.conf" "/etc/iptables/rules.v4")
    mkdir -p /root/backup_configs
    for f in "${FILES[@]}"; do
        BACKUP="/root/backup_configs/$(basename "$f").bak"
        if [[ ! -f "$BACKUP" ]]; then
            cp "$f" "$BACKUP"
            log "INFO" "Backup inicial de $f criado."
        else
            if ! diff -u "$BACKUP" "$f" > /tmp/diff_output.txt; then
                log "ALERT" "Diferenças detectadas em $f:"
                cat /tmp/diff_output.txt | tee -a "$ALERT_LOG"
                cp "$f" "$BACKUP"
            else
                log "INFO" "Nenhuma diferença em $f"
            fi
            rm /tmp/diff_output.txt
        fi
    done
}

alert_api() {
    log "INFO" "Envio de alertas via API precisa configuração específica."
    echo "Exemplo: use curl para enviar mensagens ao Telegram ou Zabbix."
}

defender_tracker() {
    log "INFO" "Rastreamento do Windows Defender deve ser feito em ambiente Windows."
}

antivirus_refresh() {
    log "INFO" "Atualizando assinaturas ClamAV..."
    freshclam
    log "INFO" "Atualização concluída."
}

kill_idle_shells() {
    log "INFO" "Procurando e matando shells ociosas com mais de 10 minutos de inatividade."

    w -h | while read -r user tty from login idle jcpu pcpu what; do
        idle_minutes=0

        if [[ "$idle" =~ ^([0-9]+):([0-9]+)$ ]]; then
            idle_minutes=$(( 10#${BASH_REMATCH[1]} * 60 + 10#${BASH_REMATCH[2]} ))
        elif [[ "$idle" =~ ^([0-9]+)$ ]]; then
            idle_minutes=${BASH_REMATCH[1]}
        else
            idle_minutes=0
        fi

        if (( idle_minutes >= 10 )); then
            pkill -kill -t "$tty" && log "ALERT" "Sessão $tty encerrada por inatividade."
        fi
    done
}

# ---------- Interface de usuário melhorada ----------

show_header() {
    clear
    echo -e "${CYAN}${BOLD}==============================================${RESET}"
    echo -e "${CYAN}${BOLD}    SCRIPT DE SEGURANÇA AVANÇADA - MENU       ${RESET}"
    echo -e "${CYAN}${BOLD}==============================================${RESET}"
    echo
}

show_menu() {
    echo -e "${YELLOW}Escolha uma opção para executar:${RESET}"
    echo -e "${GREEN}  1)${RESET} Salvaguarda automatizada dos logs"
    echo -e "${GREEN}  2)${RESET} Validador de arquivos-chave (SHA-256)"
    echo -e "${GREEN}  3)${RESET} Atualização inteligente com logging"
    echo -e "${GREEN}  4)${RESET} Coleta cirúrgica de evidências digitais"
    echo -e "${GREEN}  5)${RESET} Caçador de processos camuflados"
    echo -e "${GREEN}  6)${RESET} Sentinela de mudanças em diretórios sensíveis"
    echo -e "${GREEN}  7)${RESET} Mapeador de GPOs (Windows)"
    echo -e "${GREEN}  8)${RESET} Guardião das regras de firewall"
    echo -e "${GREEN}  9)${RESET} Auditor de permissões e compartilhamentos Windows"
    echo -e "${GREEN} 10)${RESET} Inventário enxuto e informativo"
    echo -e "${GREEN} 11)${RESET} Verificador autônomo de serviços críticos"
    echo -e "${GREEN} 12)${RESET} Bloqueador ativo de IPs hostis"
    echo -e "${GREEN} 13)${RESET} Higienizador do sistema"
    echo -e "${GREEN} 14)${RESET} Capturador de pacotes com gatilho inteligente"
    echo -e "${GREEN} 15)${RESET} Pentest interno sob demanda (Nmap + NSE)"
    echo -e "${GREEN} 16)${RESET} Comparador de configurações ao longo do tempo"
    echo -e "${GREEN} 17)${RESET} Gerador de alertas via API"
    echo -e "${GREEN} 18)${RESET} Rastreador de eventos do Defender (Windows)"
    echo -e "${GREEN} 19)${RESET} Refrescador de assinaturas de antivírus"
    echo -e "${GREEN} 20)${RESET} Vigilante de shells interativas esquecidas"
    echo -e "${RED}  0)${RESET} Sair"
    echo
}

read_option() {
    local choice
    read -rp "$(echo -e "${BOLD}Digite sua opção:${RESET} ")" choice
    echo "$choice"
}

pause_and_continue() {
    echo
    echo -e "${CYAN}Pressione ENTER para voltar ao menu principal...${RESET}"
    read -r
}

# ---------- Loop principal ----------

while true; do
    show_header
    show_menu
    opcao=$(read_option)

    case $opcao in
        1) backup_logs ;;
        2) validate_files ;;
        3) smart_update ;;
        4) collect_evidence ;;
        5) hidden_processes ;;
        6) watch_directories ;;
        7) gpo_mapper ;;
        8) firewall_guardian ;;
        9) windows_permission_audit ;;
        10) inventory_report ;;
        11) check_services ;;
        12) block_suspicious_ips ;;
        13) system_cleanup ;;
        14) packet_capture_trigger ;;
        15) internal_pentest ;;
        16) config_compare ;;
        17) alert_api ;;
        18) defender_tracker ;;
        19) antivirus_refresh ;;
        20) kill_idle_shells ;;
        0)
            echo -e "${MAGENTA}Saindo... Até logo!${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Opção inválida! Tente novamente.${RESET}"
            sleep 1.5
            ;;
    esac

    pause_and_continue
done

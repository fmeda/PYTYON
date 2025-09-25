#!/usr/bin/env bash
# Wireless Toolkit - CMNI Avançada
# Versão: 2.2.1
# Suporte previsto: 2025-2027
# Autor: [Seu Nome]
set -euo pipefail
IFS=$'\n\t'

############################################
# Configurações padrão (ajustáveis via CLI)
############################################
VERSION="2.2.1"
LOG_DIR="/var/log/wireless_toolkit"
REPORT_DIR="$LOG_DIR/reports"
TMP_BASE="/tmp"
CORE_TOOLS=(nmcli iw ip lspci lsusb)
OPTIONAL_TOOLS=(nmap wireshark aircrack-ng kismet reaver wifite speedtest-cli)
DEFAULT_MODE="passive"   # passive | active
MAX_LOG_SIZE=$((10*1024*1024)) # 10MB
TIMEOUT_NETCHECK=3

############################################
# Variáveis de runtime (alteradas por CLI)
############################################
MODE="$DEFAULT_MODE"
DRY_RUN="no"
INSTALL_OPTIONAL="no"
AUTH_FILE=""
NON_INTERACTIVE="no"
OUTPUT_DIR="$REPORT_DIR"
LOG_FILE="$LOG_DIR/wireless_toolkit.log"
REPORT_NDJSON=""   # criado em init
REPORT_JSON_FINAL=""

############################################
# Funções utilitárias e inicialização
############################################
ensure_dirs() {
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    chmod 750 "$LOG_DIR" "$REPORT_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

log() {
    local level="$1"; shift
    local msg="$*"
    local t
    t=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s | [%s] %s\n' "$t" "$level" "$msg" | tee -a "$LOG_FILE"
}

rotate_logs_if_needed() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -c%s "$LOG_FILE" || echo 0)
        if (( size > MAX_LOG_SIZE )); then
            local archived="$LOG_DIR/wireless_toolkit.log.$(date +%F_%H%M%S).gz"
            gzip -c "$LOG_FILE" > "$archived" && : > "$LOG_FILE"
            log "INFO" "Log rotacionado para $archived"
        fi
    fi
}

cleanup() {
    local rc=$?
    if [[ -d "${TMPDIR:-}" ]]; then
        rm -rf "$TMPDIR" || true
    fi
    log "INFO" "Finalizando (exit code $rc)."
    exit $rc
}
trap cleanup EXIT
trap 'log "WARN" "Interrupção pelo usuário (SIGINT/SIGTERM)"; exit 130' INT TERM

die() { log "ERROR" "$*"; exit 1; }

# cria tmp separado para execução
TMPDIR=$(mktemp -d "$TMP_BASE/wireless_toolkit.XXXX") || die "Falha ao criar TMPDIR"
export TMPDIR

# assegurar diretórios
ensure_dirs
rotate_logs_if_needed

# inicializa relatórios (NDJSON -> fácil ingestão por SIEM)
REPORT_NDJSON="$REPORT_DIR/report_$(date +%F_%T).ndjson"
REPORT_JSON_FINAL="$REPORT_DIR/report_$(date +%F_%T).json"
: > "$REPORT_NDJSON"

export_result() {
    local test="$1"; local status="$2"; local details="$3"
    # escape " e \
    details=$(printf '%s' "$details" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    printf '{"timestamp":"%s","test":"%s","status":"%s","details":"%s"}\n' \
        "$(date '+%F %T')" "$test" "$status" "$details" >> "$REPORT_NDJSON"
}

# Escrever JSON final (array) de forma atômica
finalize_json_report() {
    if [[ -s "$REPORT_NDJSON" ]]; then
        local tmpjson="${REPORT_JSON_FINAL}.tmp"
        printf "[\n" > "$tmpjson"
        # transforma NDJSON em JSON array
        sed -e '$!s/$/,/' "$REPORT_NDJSON" >> "$tmpjson"
        printf "\n]\n" >> "$tmpjson"
        mv "$tmpjson" "$REPORT_JSON_FINAL"
        log "INFO" "Relatório JSON final criado: $REPORT_JSON_FINAL"
    else
        log "WARN" "Relatório NDJSON vazio; nenhum resultado para exportar."
    fi
}

self_check() {
    log "INFO" "Executando self-check (confiabilidade)..."
    # disco disponível (em KB)
    local avail
    avail=$(df --output=avail "$REPORT_DIR" | tail -1 | tr -d '[:space:]' || echo "0")
    if [[ "$avail" -lt 10240 ]]; then
        log "ERROR" "Pouco espaço disponível em $REPORT_DIR ($avail KB). Abortando."
        die "Espaço insuficiente"
    fi

    # checa conectividade mínima (DNS/ICMP) - ínfima dependência
    if ping -c1 -W $TIMEOUT_NETCHECK 8.8.8.8 >/dev/null 2>&1; then
        log "OK" "Conectividade externa ok."
    else
        log "WARN" "Sem conectividade externa (não é fatal em modo offline)."
    fi

    # verifica ferramentas core (não instala automaticamente)
    local miss=()
    for t in "${CORE_TOOLS[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            miss+=("$t")
        fi
    done
    if (( ${#miss[@]} )); then
        log "WARN" "Ferramentas core ausentes: ${miss[*]}. Algumas funcionalidades podem ficar limitadas."
    else
        log "OK" "Ferramentas core presentes."
    fi
}

install_package() {
    local package="$1"
    if command -v "$package" &>/dev/null; then
        log "OK" "Pacote $package já instalado."
        return 0
    fi
    if [[ "$DRY_RUN" == "yes" ]]; then
        log "INFO" "[DRY-RUN] Instalaria: $package"
        return 0
    fi
    log "INFO" "Tentando instalar: $package"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y "$package"
    elif command -v dnf &>/dev/null; then
        dnf install -y "$package"
    elif command -v yum &>/dev/null; then
        yum install -y "$package"
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm "$package"
    else
        log "ERROR" "Gerenciador de pacotes não suportado. Instale $package manualmente."
        return 2
    fi
    return $?
}

check_authorization() {
    # Se modo active, exige arquivo de autorização
    if [[ "$MODE" == "active" ]]; then
        if [[ -z "$AUTH_FILE" ]]; then
            if [[ "$NON_INTERACTIVE" == "yes" ]]; then
                die "Modo active requer --auth-file quando em --non-interactive."
            fi
            # prompt interativo
            echo
            log "WARN" "Modo ACTIVE requisita autorização por escrito. Sem AUTH_FILE, abortando."
            read -rp "Deseja continuar em modo ACTIVE sem arquivo de autorização? (N) " yn
            [[ "$yn" =~ ^[Yy] ]] || die "Usuário cancelou. Forneça --auth-file."
        else
            if [[ ! -f "$AUTH_FILE" ]]; then
                die "Auth file $AUTH_FILE não encontrado."
            fi
            # registra o conteúdo (somente primeira linha)
            local firstline
            firstline=$(head -n1 "$AUTH_FILE" | tr -d '\r\n')
            log "INFO" "Autorização detectada: $firstline"
        fi
    else
        log "INFO" "Modo PASSIVE - sem ações intrusivas por padrão."
    fi
}

# -------------------------
# Funções de teste (normalizadas)
# -------------------------
run_topology_analysis() {
    log "INFO" "Topologia: início."
    if ! command -v nmcli &>/dev/null; then
        log "WARN" "nmcli não disponível; tentativa com iw/iwlist."
    fi
    local out
    if nmcli -t -f SSID,SECURITY device wifi list &>/dev/null; then
        out=$(nmcli -t -f SSID,SECURITY device wifi list || true)
        export_result "Topologia" "Sucesso" "$out"
        log "OK" "Topologia: ${out//$'\n'/; }"
    elif command -v iw &>/dev/null; then
        out=$(iw dev 2>/dev/null || echo "iw não retornou dados")
        export_result "Topologia" "Sucesso" "$out"
    else
        export_result "Topologia" "Falha" "Nenhuma ferramenta de scan disponível"
        log "ERROR" "Topologia: falha - sem ferramentas"
    fi
}

run_hardware_configuration() {
    log "INFO" "Hardware: início."
    local hw
    hw=$(lspci 2>/dev/null | grep -i -E 'wireless|network' || true)
    hw+=$'\n'
    hw+=$(lsusb 2>/dev/null | grep -i -E 'wireless|network' || true)
    export_result "Hardware" "Sucesso" "$hw"
    log "OK" "Hardware verificado."
}

run_encryption_analysis() {
    log "INFO" "Criptografia: início."
    if nmcli -t -f SSID,SECURITY device wifi list &>/dev/null; then
        local crypto
        crypto=$(nmcli -t -f SSID,SECURITY device wifi list | head -n 200)
        export_result "Criptografia" "Sucesso" "$crypto"
        log "OK" "Criptografia: amostra capturada."
    else
        export_result "Criptografia" "Indisponível" "nmcli ausente"
        log "WARN" "Criptografia: nmcli ausente."
    fi
}

run_wps_test() {
    log "INFO" "WPS: início (modo=$MODE)."
    if [[ "$MODE" == "passive" ]]; then
        export_result "WPS" "Skipped" "Modo passive - não executado"
        log "INFO" "WPS: skip em modo passive."
        return
    fi
    # modo active -> exige autorização (check_authorization já executada)
    if command -v reaver &>/dev/null; then
        export_result "WPS" "Available" "reaver presente"
        log "OK" "WPS: reaver presente (não executando ataque automaticamente)."
    else
        export_result "WPS" "NotInstalled" "reaver ausente"
        log "WARN" "WPS: reaver ausente"
    fi
}

run_performance_test() {
    log "INFO" "Performance: início."
    if command -v speedtest-cli &>/dev/null; then
        if [[ "$DRY_RUN" == "yes" ]]; then
            export_result "Performance" "DryRun" "speedtest-cli presente; execução pulada"
            log "INFO" "[DRY-RUN] speedtest-cli execução pulada."
            return
        fi
        local res
        res=$(speedtest-cli --secure --simple 2>/dev/null || echo "speedtest falhou")
        export_result "Performance" "Sucesso" "$res"
        log "OK" "Performance: $res"
    else
        export_result "Performance" "Indisponível" "speedtest-cli ausente"
        log "WARN" "Performance: speedtest-cli ausente."
    fi
}

run_integrity_test() {
    log "INFO" "Integridade: início."
    if command -v tshark &>/dev/null; then
        if [[ "$DRY_RUN" == "yes" ]]; then
            export_result "Integridade" "DryRun" "tshark presente; execução pulada"
            return
        fi
        # Captura curta e segura em modo passive; em modo active, captura com aviso
        local pcap="$TMPDIR/capture.pcap"
        if [[ "$MODE" == "passive" ]]; then
            tshark -a duration:5 -i any -w "$pcap" >/dev/null 2>&1 || true
            export_result "Integridade" "Sucesso" "Pcap curto salvo (size=$(stat -c%s "$pcap" 2>/dev/null || echo 0) bytes)"
            log "OK" "Integridade: captura curta."
        else
            # active mode: still capture but log authorization
            tshark -a duration:10 -i any -w "$pcap" >/dev/null 2>&1 || true
            export_result "Integridade" "Sucesso" "Pcap ativo salvo (size=$(stat -c%s "$pcap" 2>/dev/null || echo 0) bytes)"
            log "OK" "Integridade: captura ativa curta."
        fi
    else
        export_result "Integridade" "Indisponível" "tshark ausente"
        log "WARN" "Integridade: tshark ausente."
    fi
}

install_additional_tools() {
    log "INFO" "Instalar ferramentas adicionais (opcional)."
    if [[ "$INSTALL_OPTIONAL" != "yes" ]]; then
        log "INFO" "Instalação de opcionais não autorizada (use --install-optional)."
        return
    fi
    for pkg in "${OPTIONAL_TOOLS[@]}"; do
        install_package "$pkg" || log "WARN" "Falha ao instalar $pkg (continue)."
    done
    log "OK" "Instalação opcional concluída."
}

view_logs() { tail -n 200 "$LOG_FILE" || true; }

show_help() {
cat <<EOF
Wireless Toolkit (CMNI Avançada) v$VERSION
Uso: sudo $0 [OPÇÕES]

Opções:
  --help, -h              Exibe esta ajuda
  --version               Mostra a versão
  --mode MODE             Escolha: passive (default) | active
  --dry-run               Simula ações (não instala, não executa ataques)
  --install-optional      Permite instalar ferramentas opcionais listadas
  --auth-file PATH        Arquivo de autorização (requerido para --mode active)
  --output-dir PATH       Diretório para relatórios (default: $REPORT_DIR)
  --non-interactive       Não faz prompts interativos (fail fast se faltar auth)
  --yes                   Responde sim para prompts simples (use com cautela)
EOF
}

# -------------------------
# Argument parsing (long opts)
# -------------------------
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) show_help; exit 0 ;;
        --version) echo "$VERSION"; exit 0 ;;
        --mode) MODE="$2"; shift 2 ;;
        --dry-run) DRY_RUN="yes"; shift ;;
        --install-optional) INSTALL_OPTIONAL="yes"; shift ;;
        --auth-file) AUTH_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --non-interactive) NON_INTERACTIVE="yes"; shift ;;
        --yes) NON_INTERACTIVE="yes"; shift ;;
        --) shift; break ;;
        -*)
            echo "Opção desconhecida: $1"; show_help; exit 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
# aplicar output_dir
if [[ -n "$OUTPUT_DIR" ]]; then
    REPORT_DIR="$OUTPUT_DIR"
    mkdir -p "$REPORT_DIR"
    REPORT_NDJSON="$REPORT_DIR/report_$(date +%F_%T).ndjson"
    REPORT_JSON_FINAL="$REPORT_DIR/report_$(date +%F_%T).json"
    : > "$REPORT_NDJSON"
fi

# Re-check directories
ensure_dirs

# Segurança: exigir root para funções que precisam de privilégios
if [[ "$EUID" -ne 0 ]]; then
    die "Este script requer privilégios de root (sudo)."
fi

# Roda checks e validações de autorização
self_check
check_authorization

# -------------------------
# Menu (modo interativo simples)
# -------------------------
main_menu() {
    while true; do
        cat <<EOF
==========================
 Wireless Toolkit - Menu
 Mode: $MODE  DryRun: $DRY_RUN
 Reports: $REPORT_NDJSON
==========================
 1) Análise de Topologia
 2) Verificação de Hardware
 3) Análise de Criptografia
 4) Teste WPS (ativo somente em modo active)
 5) Teste de Performance
 6) Teste de Integridade
 7) Instalar Ferramentas Opcionais
 8) Ver logs
 9) Gerar JSON final e sair
 15) Sair sem gerar JSON
EOF
        read -rp "Escolha: " opt
        case "$opt" in
            1) run_topology_analysis ;;
            2) run_hardware_configuration ;;
            3) run_encryption_analysis ;;
            4) run_wps_test ;;
            5) run_performance_test ;;
            6) run_integrity_test ;;
            7) install_additional_tools ;;
            8) view_logs ;;
            9) finalize_json_report; break ;;
            15) log "INFO" "Saída solicitada pelo usuário (sem gerar JSON final)"; break ;;
            *) echo "Opção inválida." ;;
        esac
        echo "Pressione ENTER para continuar..."
        read -r _
    done
}

# Se chamado com argumentos não-interativos (scripted), executa um fluxo padrão
if [[ "$NON_INTERACTIVE" == "yes" ]]; then
    log "INFO" "Executando em modo non-interactive: fluxo padrão."
    run_topology_analysis
    run_hardware_configuration
    run_encryption_analysis
    run_integrity_test
    run_performance_test
    finalize_json_report
    exit 0
fi

# Caso contrário entra no menu interativo
log "INFO" "Inicialização completa. Entrando em modo interativo."
main_menu
finalize_json_report
log "INFO" "Execução concluída. Relatórios: $REPORT_NDJSON $REPORT_JSON_FINAL"
exit 0

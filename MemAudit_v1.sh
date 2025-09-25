#!/bin/bash
# =============================================================================
# MemGuard - Advanced Memory Manager & Secure Auditor
# =============================================================================
# Recursos:
# - Pré-check e instalação de dependências
# - Autenticação híbrida (LDAP, PAM, Vault)
# - Interface CLI interativa
# - Segurança de credenciais (apagadas no final da sessão)
# - Relatórios estruturados
# - Auditoria cifrada AES-256
# =============================================================================

# ---------------------- CONFIGURAÇÃO DE CORES ----------------------
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"

# ---------------------- VARIÁVEIS GLOBAIS ----------------------
LOG_FILE="/var/log/memguard_audit.log.enc"
LOG_KEY_FILE="/tmp/memguard_key_$$"

# ---------------------- FUNÇÃO HELP ----------------------
show_help() {
    cat << EOF
MemGuard - Ferramenta Corporativa de Gerenciamento de Memória

USO:
  $0 [opções]

OPÇÕES:
  --help           Mostra esta ajuda
  --menu           Abre o menu interativo
  --check          Checagem rápida de memória
  --report         Gera relatório detalhado
  --auth <tipo>    Define autenticação (ldap | pam | vault)

EXEMPLOS:
  $0 --menu
  $0 --check
  $0 --auth ldap --report

EOF
}

# ---------------------- PRÉ-CHECK ----------------------
pre_check() {
    echo -e "${BLUE}[INFO] Verificando dependências...${RESET}"
    local deps=(free awk bc ldapwhoami pamtester vault openssl)
    local missing=()

    for pkg in "${deps[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[WARN] Instalando dependências ausentes: ${missing[*]}${RESET}"
        sudo apt-get update -qq && sudo apt-get install -y "${missing[@]}"
    else
        echo -e "${GREEN}[OK] Todas as dependências estão presentes.${RESET}"
    fi
}

# ---------------------- AUDITORIA CIFRADA ----------------------
log_action() {
    local action="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if [[ ! -f "$LOG_KEY_FILE" ]]; then
        head -c 32 /dev/urandom > "$LOG_KEY_FILE"
    fi

    echo "[$timestamp] USER=$USERNAME ACTION=$action" \
        | openssl enc -aes-256-cbc -a -pbkdf2 -salt \
        -pass file:"$LOG_KEY_FILE" >> "$LOG_FILE"
}

# ---------------------- AUTENTICAÇÃO ----------------------
ask_credentials() {
    local method=$1
    case "$method" in
        ldap)
            read -rp "Usuário LDAP: " USERNAME
            read -rsp "Senha LDAP: " PASSWORD
            echo
            ldapwhoami -x -D "uid=${USERNAME},ou=People,dc=empresa,dc=com" -w "${PASSWORD}" &>/dev/null
            [[ $? -eq 0 ]] && echo -e "${GREEN}[OK] Autenticação LDAP.${RESET}" || { echo -e "${RED}[ERRO] LDAP falhou.${RESET}"; exit 1; }
            ;;
        pam)
            read -rp "Usuário do sistema: " USERNAME
            read -rsp "Senha: " PASSWORD
            echo
            echo "$PASSWORD" | pamtester login "$USERNAME" authenticate &>/dev/null
            [[ $? -eq 0 ]] && echo -e "${GREEN}[OK] Autenticação PAM.${RESET}" || { echo -e "${RED}[ERRO] PAM falhou.${RESET}"; exit 1; }
            ;;
        vault)
            read -rsp "Token Vault: " VAULT_TOKEN
            echo
            export VAULT_ADDR="https://vault.empresa.com:8200"
            vault login "$VAULT_TOKEN" &>/dev/null
            [[ $? -eq 0 ]] && echo -e "${GREEN}[OK] Autenticação Vault.${RESET}" || { echo -e "${RED}[ERRO] Vault falhou.${RESET}"; exit 1; }
            ;;
        *)
            echo -e "${RED}[ERRO] Método de autenticação inválido.${RESET}"
            exit 1
            ;;
    esac

    log_action "LOGIN método=$method"
}

# ---------------------- FUNÇÕES DE MEMÓRIA ----------------------
check_memory() {
    free -h
    log_action "CHECK_MEMORY"
}

generate_report() {
    local outfile="memguard_report_$(date +%Y%m%d_%H%M%S).txt"
    echo "Relatório MemGuard - $(date)" > "$outfile"
    free -h >> "$outfile"
    echo -e "${GREEN}[OK] Relatório gerado: $outfile${RESET}"
    log_action "GENERATE_REPORT $outfile"
}

# ---------------------- MENU CLI ----------------------
menu() {
    while true; do
        echo -e "${BLUE}===== MEMGUARD MENU =====${RESET}"
        echo "1) Verificar memória"
        echo "2) Gerar relatório"
        echo "3) Trocar método de autenticação"
        echo "4) Sair"
        read -rp "Escolha uma opção: " opt

        case $opt in
            1) check_memory ;;
            2) generate_report ;;
            3) read -rp "Novo método (ldap|pam|vault): " AUTH_METHOD; ask_credentials "$AUTH_METHOD" ;;
            4) echo -e "${YELLOW}[INFO] Encerrando sessão...${RESET}"; log_action "LOGOUT"; break ;;
            *) echo -e "${RED}[ERRO] Opção inválida.${RESET}" ;;
        esac
    done
}

# ---------------------- LIMPEZA ----------------------
cleanup() {
    unset USERNAME PASSWORD VAULT_TOKEN
    shred -u "$LOG_KEY_FILE" 2>/dev/null
    echo -e "${YELLOW}[INFO] Credenciais e chave de auditoria limpas.${RESET}"
}
trap cleanup EXIT

# ---------------------- EXECUÇÃO ----------------------
main() {
    pre_check

    local AUTH_METHOD="pam" # default
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --menu) MODE="menu"; shift ;;
            --check) MODE="check"; shift ;;
            --report) MODE="report"; shift ;;
            --auth) AUTH_METHOD="$2"; shift 2 ;;
            *) echo -e "${RED}[ERRO] Opção inválida: $1${RESET}"; show_help; exit 1 ;;
        esac
    done

    ask_credentials "$AUTH_METHOD"

    case $MODE in
        menu) menu ;;
        check) check_memory ;;
        report) generate_report ;;
        *) show_help ;;
    esac
}

main "$@"

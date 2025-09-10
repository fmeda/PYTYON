#!/bin/bash
# ================================================
# Módulo de Gerenciamento de Variáveis CMNI 2025+
# ================================================

# Pré-check: verificar se a função de log está disponível
function precheck_variable_module() {
    if ! declare -F log_action &>/dev/null; then
        echo "[ERRO] Função log_action não encontrada. Carregue este módulo via script principal."
        exit 1
    fi
}

# -------------------------------
# Função --help do módulo
# -------------------------------
function help_variable_module() {
cat <<EOF
========================================
Módulo de Variáveis CMNI 2025+
========================================

Funções disponíveis:

1) show_variables         - Exibe as variáveis críticas SNORT/pfSense.
2) update_variable        - Atualiza o valor de uma variável com auditoria.
3) variable_module_menu   - Menu interativo do módulo.
4) help_variable_module   - Exibe esta ajuda.
EOF
}

# -------------------------------
# Função para exibir variáveis
# -------------------------------
function show_variables() {
    echo "=== Variáveis CMNI 2025+ ==="
    echo "1) SNORT_RULES_UPDATE: $SNORT_RULES_UPDATE"
    echo "2) PFSENSE_INITIAL_CONFIG: $PFSENSE_INITIAL_CONFIG"
}

# -------------------------------
# Função para atualizar variáveis
# -------------------------------
function update_variable() {
    show_variables
    echo "Escolha a variável para atualizar (1 ou 2):"
    read -rp "> " choice
    case "$choice" in
        1)
            read -rp "Digite novo valor para SNORT_RULES_UPDATE: " new_value
            if [[ -z "$new_value" ]]; then
                echo "[WARN] Valor não pode ser vazio."
                return
            fi
            SNORT_RULES_UPDATE="$new_value"
            log_action "Variável SNORT_RULES_UPDATE atualizada para: $new_value"
            ;;
        2)
            read -rp "Digite novo valor para PFSENSE_INITIAL_CONFIG: " new_value
            if [[ -z "$new_value" ]]; then
                echo "[WARN] Valor não pode ser vazio."
                return
            fi
            PFSENSE_INITIAL_CONFIG="$new_value"
            log_action "Variável PFSENSE_INITIAL_CONFIG atualizada para: $new_value"
            ;;
        *)
            echo "[WARN] Opção inválida."
            ;;
    esac
}

# -------------------------------
# Menu interativo do módulo
# -------------------------------
function variable_module_menu() {
    precheck_variable_module
    while true; do
        echo "=== Módulo de Variáveis CMNI 2025+ ==="
        echo "1) Visualizar variáveis"
        echo "2) Atualizar variável"
        echo "3) Ajuda (--help)"
        echo "0) Voltar ao menu principal"
        read -rp "Escolha uma opção: " opt
        case "$opt" in
            1) show_variables ;;
            2) update_variable ;;
            3) help_variable_module ;;
            0) break ;;
            *) echo "[WARN] Opção inválida." ;;
        esac
    done
}

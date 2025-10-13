#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# triple_luks_advanced.sh
# Autor: Fabiano Aparecido
# Versão: 4.0
# Descrição: Criptografia em 3 camadas com self-wipe seguro, restore automático,
# runbook embutido, logging, métricas e boas práticas CMMI V2.0 ML2/ML3.

set -euo pipefail

###########################
# Configurações do Script #
###########################

WORKDIR="${WORKDIR:-$HOME/triple_luks_advanced}"
DISKIMG="$WORKDIR/disk.img"
MAX_ATTEMPTS=3
ATT_FILE="$WORKDIR/attempts.counter"
LOG_FILE="$WORKDIR/script_audit.log"
METRICS_FILE="$WORKDIR/metrics.json"

SELFWIPE="${SELFWIPE:-0}"   # 0 = alerta, 1 = destrutivo

KEYFILES=(
    "$WORKDIR/key_layer1.bin.gpg"
    "$WORKDIR/key_layer2.bin.gpg"
    "$WORKDIR/key_layer3.bin.gpg"
)

BACKUP_HEADERS=(
    "$WORKDIR/header_l1.backup"
    "$WORKDIR/header_l2.backup"
    "$WORKDIR/header_l3.backup"
)

#####################
# Funções utilitárias #
#####################

log() {
    echo "$(date +'%F %T') | $*" | tee -a "$LOG_FILE"
}

record_metric() {
    local key="$1"
    local value="$2"
    if [[ ! -f "$METRICS_FILE" ]]; then
        echo "{}" > "$METRICS_FILE"
    fi
    tmp=$(mktemp)
    jq --arg k "$key" --argjson v "$value" '.[$k]=$v' "$METRICS_FILE" > "$tmp" && mv "$tmp" "$METRICS_FILE"
}

increment_attempt() {
    local curr=$(cat "$ATT_FILE")
    curr=$((curr+1))
    echo "$curr" > "$ATT_FILE"
    log "Tentativas falhas: $curr/$MAX_ATTEMPTS"
    record_metric "attempt_failure_count" "$curr"

    if (( curr >= MAX_ATTEMPTS )); then
        log "Limite de tentativas atingido ($MAX_ATTEMPTS)."
        if (( SELFWIPE == 1 )); then
            double_confirm_selfwipe
        else
            log "SELF-WIPE desativado (SELFWIPE=0). Para ativar, export SELFWIPE=1"
        fi
        restore_headers
        exit 1
    fi
}

reset_attempt() {
    echo 0 > "$ATT_FILE"
    log "Contador de tentativas resetado."
    record_metric "attempt_failure_count" 0
}

decrypt_keyfile() {
    local gpgfile="$1"
    local outfile=$(mktemp)
    gpg --decrypt "$gpgfile" > "$outfile"
    chmod 600 "$outfile"
    echo "$outfile"
}

backup_headers() {
    log "Realizando backup dos headers LUKS..."
    sudo cryptsetup luksHeaderBackup "$LOOPDEV" --header-backup-file "${BACKUP_HEADERS[0]}"
    [[ -e /dev/mapper/l1 ]] && sudo cryptsetup luksHeaderBackup /dev/mapper/l1 --header-backup-file "${BACKUP_HEADERS[1]}"
    [[ -e /dev/mapper/l2 ]] && sudo cryptsetup luksHeaderBackup /dev/mapper/l2 --header-backup-file "${BACKUP_HEADERS[2]}"
    log "Backups concluídos."
}

restore_headers() {
    log "Tentando restaurar headers a partir de backup..."
    for i in {0..2}; do
        if [[ -f "${BACKUP_HEADERS[$i]}" ]]; then
            sudo cryptsetup luksHeaderRestore "$LOOPDEV" --header-backup-file "${BACKUP_HEADERS[$i]}" && \
            log "Header layer $((i+1)) restaurado."
        fi
    done
}

double_confirm_selfwipe() {
    log "ATENÇÃO: Você está prestes a destruir os dados."
    read -p "Digite 'CONFIRMAR' para continuar: " input1
    if [[ "$input1" != "CONFIRMAR" ]]; then
        log "Self-wipe abortado."
        return
    fi
    read -p "Digite novamente 'DESTRUIR' para confirmar a destruição: " input2
    if [[ "$input2" == "DESTRUIR" ]]; then
        log "Executando SELF-WIPE DESTRUTIVO no $DISKDEV"
        dd if=/dev/urandom of="$DISKIMG" bs=1M status=progress conv=notrunc
        log "Self-wipe concluído."
    else
        log "Self-wipe abortado na segunda confirmação."
    fi
}

open_layer() {
    local layer="$1"
    local device="$2"
    local keyfile="$3"

    if [[ ! -e "$device" ]]; then
        log "Dispositivo $device não existe. Falha ao abrir $layer."
        increment_attempt
        return 1
    fi

    sudo cryptsetup open --key-file "$keyfile" "$device" "$layer" && \
    log "Camada $layer aberta com sucesso."
}

close_layers() {
    for layer in l3 l2 l1; do
        [[ -e "/dev/mapper/$layer" ]] && sudo cryptsetup close "$layer" && log "Layer $layer fechada."
    done
}

mount_layer3() {
    local mount_point="$WORKDIR/secure"
    sudo mkdir -p "$mount_point"
    sudo mount /dev/mapper/l3 "$mount_point"
    log "Layer3 montada em $mount_point"
    record_metric "last_mount_time" "$(date +%s)"
}

unmount_layer3() {
    sudo umount "$WORKDIR/secure" || true
    log "Layer3 desmontada."
}

#######################
# Execução principal #
#######################

log "=== INÍCIO DO SCRIPT TRIPLE LUKS ADVANCED ==="

mkdir -p "$WORKDIR"
touch "$ATT_FILE" "$LOG_FILE" "$METRICS_FILE"

LOOPDEV=$(losetup --show -f "$DISKIMG")
log "Loop device associado: $LOOPDEV"

backup_headers

KEY1=$(decrypt_keyfile "${KEYFILES[0]}")
KEY2=$(decrypt_keyfile "${KEYFILES[1]}")
KEY3=$(decrypt_keyfile "${KEYFILES[2]}")

open_layer l1 "$LOOPDEV" "$KEY1" || exit 1
open_layer l2 /dev/mapper/l1 "$KEY2" || exit 1
open_layer l3 /dev/mapper/l2 "$KEY3" || exit 1

mount_layer3

shred -u "$KEY1" "$KEY2" "$KEY3" || rm -f "$KEY1" "$KEY2" "$KEY3"

log "=== SCRIPT CONCLUÍDO COM SUCESSO ==="

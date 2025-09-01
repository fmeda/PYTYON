#!/usr/bin/env bash
# admin_reference_linux.sh
# Referência Profissional: Hardening, Backup (criptografado), Monitoramento, Rollback
# Versão: 3.0
set -euo pipefail
IFS=$'\n\t'
umask 027

# ---------------------------
#  CONSTANTS / DEFAULTS
# ---------------------------
SCRIPTNAME=$(basename "$0")
LOGFILE=${LOGFILE:-/var/log/admin_reference.log}
SYSLOG_TAG="admin_reference"
BACKUP_BASE=${BACKUP_BASE:-/var/backups/admin_reference}
CONFIG_BACKUP_DIR="${BACKUP_BASE}/config_backups"
PAYLOAD_BACKUP_DIR="${BACKUP_BASE}/payloads"
RETENTION_DAYS=${RETENTION_DAYS:-30}
DRYRUN=0
GPG_RECIPIENT=${GPG_RECIPIENT:-""}        # prefer GPG recipient (email / keyid)
ENC_PASSPHRASE=${ENC_PASSPHRASE:-""}      # fallback symmetric encryption (use env var from Vault in prod)
SIGNING_KEY=${SIGNING_KEY:-""}            # optional GPG key id for signing manifest
ZABBIX_SERVER=${ZABBIX_SERVER:-""}        # if set, will try to send metrics
ZABBIX_KEY=${ZABBIX_KEY:-"admin_reference.backup.status"}

# ---------------------------
#  HELP
# ---------------------------
usage(){
  cat <<EOF
Usage: $SCRIPTNAME [--action ACTION] [options]

ACTIONS:
  harden          - apply hardening changes (creates backups of configs)
  backup          - create encrypted backup of target paths
  restore         - restore payload backup (provide --file)
  undo-harden     - rollback latest hardening changes
  status          - check health and dependencies
  help            - this message

COMMON OPTIONS:
  --sources "PATHS"       (e.g. '/etc /var/www')
  --backup-file FILE      (for restore)
  --dry-run               simulate actions
  --retain DAYS           retention days for backups
  --gpg-recipient X       GPG recipient (preferred)
  --enc-passphrase STR    symmetric passphrase fallback (from vault)
  --sign-key KEY          GPG key id to sign manifest
  --zabbix-server HOST
  -h, --help

Note: run as root (sudo). Do NOT hardcode secrets in files; use env vars or Vault.
EOF
  exit 1
}

# ---------------------------
#  SIGNALS (Ctrl+C)
# ---------------------------
trap 'echo -e "\n[⚠] Interrompido pelo usuário. Saindo com segurança..."; exit 130' INT TERM

# ---------------------------
#  LOGGING helpers (file + syslog)
# ---------------------------
_log_json() {
  local level="$1"; shift
  local message="$*"
  local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local entry; entry=$(cat <<JSON
{"ts":"$ts","level":"$level","host":"$(hostname -f)","pid":$$,"msg":"$message"}
JSON
)
  # append safe-file log
  mkdir -p "$(dirname "$LOGFILE")"
  printf "%s\n" "$entry" >> "$LOGFILE"
  chmod 600 "$LOGFILE"
  # send to syslog
  logger -t "$SYSLOG_TAG" -p user."${level,,}" "$message" || true
}

info(){ _log_json "INFO" "$*"; echo "[INFO] $*"; }
warn(){ _log_json "WARN" "$*"; echo "[WARN] $*"; }
err(){ _log_json "ERROR" "$*"; echo "[ERROR] $*" >&2; }

# ---------------------------
#  ARG PARSING
# ---------------------------
ACTION=""
SOURCES="/etc /var/www"
RESTORE_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --action) ACTION="$2"; shift 2;;
    --sources) SOURCES="$2"; shift 2;;
    --backup-file) RESTORE_FILE="$2"; shift 2;;
    --dry-run) DRYRUN=1; shift;;
    --retain) RETENTION_DAYS="$2"; shift 2;;
    --gpg-recipient) GPG_RECIPIENT="$2"; shift 2;;
    --enc-passphrase) ENC_PASSPHRASE="$2"; shift 2;;
    --sign-key) SIGNING_KEY="$2"; shift 2;;
    --zabbix-server) ZABBIX_SERVER="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

# ---------------------------
#  ENV checks
# ---------------------------
require_root(){ if [ "$(id -u)" -ne 0 ]; then err "Execute como root (sudo)"; exit 2; fi; }
ensure_dir(){ local d="$1"; mkdir -p "$d"; chmod 700 "$d"; }

# ---------------------------
#  DEPENDENCIES pre-check & install (APT-based)
# ---------------------------
check_and_install_pkg(){
  local pkg="$1"
  if ! command -v "$pkg" &>/dev/null; then
    warn "Pacote $pkg não encontrado. Tentando instalar (APT)..."
    if command -v apt-get &>/dev/null; then
      if [ "$DRYRUN" -eq 1 ]; then
        info "[DRYRUN] apt-get install -y $pkg"
      else
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg"
        info "Instalado $pkg"
      fi
    else
      err "Gerenciador de pacotes não suportado neste host. Instale $pkg manualmente."
      return 1
    fi
  else
    info "Dependência OK: $pkg"
  fi
}

precheck_deps(){
  info "Validando dependências essenciais..."
  for p in tar rsync gpg zabbix_sender openssl logger; do
    check_and_install_pkg "$p" || true
  done
}

# ---------------------------
#  BACKUP: create_payload_backup (tar -> checksum -> encrypt -> manifest)
# ---------------------------
timestamp(){ date -u +"%Y%m%dT%H%M%SZ"; }

create_payload_backup(){
  local ts; ts=$(timestamp)
  local payload_tar="${PAYLOAD_BACKUP_DIR}/payload_${ts}.tar"
  local payload_gz="${payload_tar}.gz"
  local payload_enc  # final file
  ensure_dir "$PAYLOAD_BACKUP_DIR"

  info "Criando tar dos sources: $SOURCES -> $payload_tar"
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] tar -cf $payload_tar $SOURCES"
  else
    tar -cf "$payload_tar" $SOURCES
    gzip -9 "$payload_tar"
  fi

  # checksum
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] geraria SHA256 para $payload_gz"
  else
    sha256sum "$payload_gz" > "${payload_gz}.sha256"
    info "SHA256 criado: ${payload_gz}.sha256"
  fi

  # manifest
  local manifest="${PAYLOAD_BACKUP_DIR}/manifest_${ts}.json"
  cat > "$manifest" <<EOF
{
  "host": "$(hostname -f)",
  "timestamp": "$ts",
  "payload": "$(basename "$payload_gz")",
  "sha256": "$(cut -d' ' -f1 ${payload_gz}.sha256 || echo 'DRYRUN')",
  "gpg_recipient": "$GPG_RECIPIENT",
  "enc_method": "$([ -n "$GPG_RECIPIENT" ] && echo "gpg" || echo "openssl")"
}
EOF
  chmod 600 "$manifest"
  info "Manifest criado: $manifest"

  # optional manifest signature
  if [ -n "$SIGNING_KEY" ] && [ "$DRYRUN" -eq 0 ]; then
    gpg --batch --yes -u "$SIGNING_KEY" --detach-sign -o "${manifest}.sig" "$manifest" \
      && info "Manifest assinado ($SIGNING_KEY): ${manifest}.sig" || warn "Falha ao assinar manifest"
  fi

  # encrypt
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] encrypt passo (gpg/openssl) omitido"
    payload_enc="${payload_gz}.enc"
  else
    if [ -n "$GPG_RECIPIENT" ]; then
      info "Criptografando com GPG para ${GPG_RECIPIENT}..."
      gpg --yes -e -r "$GPG_RECIPIENT" -o "${payload_gz}.gpg" "$payload_gz"
      payload_enc="${payload_gz}.gpg"
    elif [ -n "$ENC_PASSPHRASE" ]; then
      info "Criptografando com OpenSSL (AES-256-CBC) usando ENC_PASSPHRASE..."
      openssl enc -aes-256-cbc -pbkdf2 -salt -in "$payload_gz" -out "${payload_gz}.enc" -pass pass:"$ENC_PASSPHRASE"
      payload_enc="${payload_gz}.enc"
    else
      warn "Nenhuma forma de criptografia configurada: defina GPG_RECIPIENT ou ENC_PASSPHRASE. Salvando tar.gz sem criptografia."
      payload_enc="$payload_gz"
    fi
    # shred originals
    if [ -n "${payload_gz}" ] && [ -f "${payload_gz}" ]; then
      shred -u "${payload_gz}" || true
    fi
  fi

  info "Backup final: $payload_enc"
  echo "$payload_enc"
}

# ---------------------------
#  RESTORE: decrypt -> extract
# ---------------------------
restore_payload(){
  local file="$1"
  if [ -z "$file" ] || [ ! -f "$file" ]; then err "Arquivo de backup não informado ou inexistente"; return 2; fi
  local tmpdir; tmpdir=$(mktemp -d /tmp/adminref_restore.XXXX)
  info "Restaurando backup $file -> tmpdir=$tmpdir"

  if [[ "$file" == *.gpg ]]; then
    info "Descriptografando GPG..."
    if [ "$DRYRUN" -eq 1 ]; then
      info "[DRYRUN] gpg --output ... --decrypt $file"
    else
      gpg --yes --decrypt -o "${tmpdir}/payload.gz" "$file"
    fi
  elif [[ "$file" == *.enc ]]; then
    info "Descriptografando OpenSSL..."
    if [ -z "$ENC_PASSPHRASE" ]; then err "ENC_PASSPHRASE não definida para descriptografia"; return 3; fi
    if [ "$DRYRUN" -eq 1 ]; then
      info "[DRYRUN] openssl enc -d -aes-256-cbc ... $file"
    else
      openssl enc -d -aes-256-cbc -pbkdf2 -in "$file" -out "${tmpdir}/payload.gz" -pass pass:"$ENC_PASSPHRASE"
    fi
  else
    info "Arquivo sem extensão conhecida, assumindo tar.gz"
    cp -a "$file" "${tmpdir}/payload.gz"
  fi

  # extract
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] tar -xzf ${tmpdir}/payload.gz -C / --list"
  else
    gunzip -c "${tmpdir}/payload.gz" | tar -x -C /
    info "Restauração aplicada (extraída para /). Verifique serviços e permissões."
  fi
  rm -rf "$tmpdir"
}

# ---------------------------
#  HARDEN: create config backups + apply changes (idempotent) + record act
#  - backup_and_record(file): copies file to CONFIG_BACKUP_DIR + sha256 + manifest
#  - apply_change: minimal set: sshd_config hardening and ufw rules
# ---------------------------
backup_and_record_config(){
  local src="$1"
  ensure_dir "$CONFIG_BACKUP_DIR"
  local ts; ts=$(timestamp)
  if [ ! -f "$src" ]; then warn "Arquivo $src não existe, pulando backup"; return 0; fi
  local dst="${CONFIG_BACKUP_DIR}/$(basename "$src").${ts}"
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] cp -p $src $dst"
    return 0
  fi
  cp -a "$src" "$dst"
  chmod 600 "$dst"
  sha256sum "$dst" > "${dst}.sha256"
  info "Backup config: $dst (sha256 -> ${dst}.sha256)"
  # record manifest
  echo "{\"file\":\"$src\",\"backup\":\"$dst\",\"ts\":\"$ts\",\"host\":\"$(hostname -f)\"}" >> "${CONFIG_BACKUP_DIR}/changes_manifest.log"
  chmod 600 "${CONFIG_BACKUP_DIR}/changes_manifest.log"
}

apply_sshd_hardening(){
  local conf="/etc/ssh/sshd_config"
  backup_and_record_config "$conf"
  # minimal idempotent changes
  _set_sshd_option(){ local key="$1" val="$2"; if grep -qE "^\s*${key}\s+" "$conf"; then sed -ri "s|^\s*${key}\s+.*|${key} ${val}|" "$conf"; else echo "${key} ${val}" >> "$conf"; fi; }
  if [ "$DRYRUN" -eq 1 ]; then
    info "[DRYRUN] Would set sshd options (PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3)"
  else
    _set_sshd_option PermitRootLogin no
    _set_sshd_option PasswordAuthentication no
    _set_sshd_option MaxAuthTries 3
    systemctl reload sshd || systemctl restart sshd || warn "sshd reload failed"
    info "sshd hardened"
  fi
}

apply_ufw_hardening(){
  if command -v ufw &>/dev/null; then
    if [ "$DRYRUN" -eq 1 ]; then
      info "[DRYRUN] ufw default deny incoming; ufw allow ssh; ufw --force enable"
    else
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow ssh
      ufw --force enable
      info "UFW configurado"
    fi
  else
    warn "ufw não instalado; pular UFW hardening"
  fi
}

# ---------------------------
#  UNDO (rollback) harness:
#  - Undo latest hardening will look at CONFIG_BACKUP_DIR and restore last backups for known files
# ---------------------------
undo_hardening(){
  info "Executando rollback de hardening (restore dos últimos backups de config)"
  for file in /etc/ssh/sshd_config; do
    # find latest backup for this filename
    local latest
    latest=$(ls -1t "${CONFIG_BACKUP_DIR}/$(basename "$file")."* 2>/dev/null | head -n1 || true)
    if [ -n "$latest" ]; then
      if [ "$DRYRUN" -eq 1 ]; then
        info "[DRYRUN] cp -p $latest $file"
      else
        cp -a "$latest" "$file"
        chmod 600 "$file"
        systemctl reload sshd || true
        info "Restaurado $file a partir de $latest"
      fi
    else
      warn "Nenhum backup encontrado para $file"
    fi
  done
}

# ---------------------------
#  ROTATION (simple)
# ---------------------------
rotate_backups(){
  info "Rotacionando backups com mais de ${RETENTION_DAYS} dias"
  find "$BACKUP_BASE" -type f -mtime +"$RETENTION_DAYS" -print -exec rm -fv {} \; || true
}

# ---------------------------
#  STATUS check (health)
# ---------------------------
status_check(){
  info "Status check: disk, services, dependencies"
  df -h /
  if command -v zabbix_sender &>/dev/null && [ -n "$ZABBIX_SERVER" ]; then
    zabbix_sender -z "$ZABBIX_SERVER" -s "$(hostname -s)" -k "$ZABBIX_KEY" -o 0 || warn "zabbix_sender falhou"
  fi
}

# ---------------------------
#  MAIN
# ---------------------------
main(){
  require_root
  ensure_dir "$BACKUP_BASE"
  ensure_dir "$CONFIG_BACKUP_DIR"
  ensure_dir "$PAYLOAD_BACKUP_DIR"
  precheck_deps

  case "$ACTION" in
    harden)
      info "Iniciando hardening (DRYRUN=$DRYRUN)"
      apply_sshd_hardening
      apply_ufw_hardening
      info "Hardening finalizado"
      ;;
    backup)
      info "Iniciando backup (DRYRUN=$DRYRUN)"
      local out
      out=$(create_payload_backup)
      info "Backup criado: $out"
      rotate_backups
      ;;
    restore)
      info "Restaurar não implementado diretamente nesta chamada; use --backup-file FILE com --action restore"
      if [ -n "$RESTORE_FILE" ]; then
        restore_payload "$RESTORE_FILE"
      else
        err "Defina --backup-file FILE"
        exit 2
      fi
      ;;
    undo-harden)
      undo_hardening
      ;;
    status)
      status_check
      ;;
    "")
      usage
      ;;
    *)
      err "Ação desconhecida: $ACTION"
      usage
      ;;
  esac
}

require_root(){ if [ "$(id -u)" -ne 0 ]; then err "Execute como root (sudo)"; exit 2; fi; }
main

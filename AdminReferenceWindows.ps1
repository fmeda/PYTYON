<#
AdminReferenceWindows.ps1 - versão 3.0
Hardening, Backup criptografado, Monitoramento, Rollback básico
Execute como Administrator.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)][ValidateSet("harden","backup","restore","undo-harden","status")][string]$Action = "status",
  [string]$Sources = "C:\Windows\System32\config;C:\inetpub\wwwroot",
  [string]$BackupDest = "D:\Backups\AdminReference",
  [string]$GpgRecipient = "",
  [string]$EncPassphrase = "",
  [string]$BackupFile = "",
  [switch]$DryRun
)

# ---------- Helpers ----------
function Write-LogJson {
  param($Level,$Message)
  $entry = @{ ts = (Get-Date).ToUniversalTime().ToString("s") + "Z"; level=$Level; host=$env:COMPUTERNAME; msg=$Message }
  $logPath = Join-Path -Path $env:ProgramData -ChildPath "AdminReference\admin_reference.log"
  New-Item -Path (Split-Path $logPath) -ItemType Directory -Force | Out-Null
  $entry | ConvertTo-Json -Compress | Out-File -FilePath $logPath -Append -Encoding utf8
  Write-EventLog -LogName Application -Source "AdminReference" -EntryType Information -EventId 1000 -Message $Message -ErrorAction SilentlyContinue
  Write-Host "[$Level] $Message"
}

# Ctrl+C friendly
$null = Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {
  Write-LogJson "WARN" "Interrupção (Ctrl+C) detectada. Encerrando..."
  exit 130
}

# Pre-checks: modules and tools
function Ensure-Module {
  param($Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-LogJson "WARN" "Módulo $Name não instalado. Tentando instalar via PSGallery..."
    if ($DryRun) { Write-LogJson "INFO" "[DRYRUN] Install-Module $Name -Force -Scope CurrentUser"; return }
    Install-Module -Name $Name -Force -Scope CurrentUser -ErrorAction Stop
    Write-LogJson "INFO" "Módulo $Name instalado"
  } else { Write-LogJson "INFO" "Módulo $Name OK" }
}

# ---------------------------
# Hardening (exemplos idempotentes)
# ---------------------------
function Invoke-Hardening {
  Write-LogJson "INFO" "Aplicando hardening (idempotente)"
  if ($DryRun) { Write-LogJson "INFO" "[DRYRUN] Set-ExecutionPolicy AllSigned -Force" } else { Set-ExecutionPolicy AllSigned -Force }
  # Exemplo: firewall rules
  if ($DryRun) { Write-LogJson "INFO" "[DRYRUN] Enable-NetFirewallProfile -Profile Domain,Private,Public" } else { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True }
  Write-LogJson "INFO" "Hardening concluído"
}

# ---------------------------
# Backup: compress + encrypt
#    - If 7z available, use AES-256; else use Compress-Archive (no built-in strong symmetric)
#    - GPG: if available and recipient provided, use gpg
# ---------------------------
function Invoke-Backup {
  param($SourcesList)
  $ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $destDir = Join-Path $BackupDest $ts
  if ($DryRun) { Write-LogJson "INFO" "[DRYRUN] Criaria pasta $destDir" ; return }
  New-Item -ItemType Directory -Path $destDir -Force | Out-Null

  $sources = $SourcesList -split ";"
  foreach ($s in $sources) {
    $name = Split-Path $s -Leaf
    $target = Join-Path $destDir $name
    Write-LogJson "INFO" "Copiando $s -> $target"
    robocopy $s $target /MIR /R:2 /W:2 | Out-Null
  }

  # compress
  $archive = Join-Path $BackupDest "payload_$ts.zip"
  Write-LogJson "INFO" "Compactando -> $archive"
  Compress-Archive -Path (Join-Path $destDir "*") -DestinationPath $archive -Force

  # SHA256
  $hash = Get-FileHash -Path $archive -Algorithm SHA256
  $hashPath = "$archive.sha256"
  $hash.Hash | Out-File -FilePath $hashPath

  # encrypt (prefer GPG if provided)
  if ($GpgRecipient -and (Get-Command gpg -ErrorAction SilentlyContinue)) {
    Write-LogJson "INFO" "Criptografando com GPG para $GpgRecipient"
    & gpg --yes -e -r $GpgRecipient -o "$archive.gpg" $archive
    Remove-Item $archive -Force
    $final = "$archive.gpg"
  } elseif ($EncPassphrase) {
    # Use 7z if present for AES-256
    if (Get-Command 7z -ErrorAction SilentlyContinue) {
      Write-LogJson "INFO" "Criptografando com 7z AES-256"
      & 7z a -t7z -mhe=on -p"$EncPassphrase" "$archive.7z" $archive | Out-Null
      Remove-Item $archive -Force
      $final = "$archive.7z"
    } else {
      Write-LogJson "WARN" "7z não disponível. Arquivo ficará sem criptografia. Instale 7zip ou GPG."
      $final = $archive
    }
  } else {
    Write-LogJson "WARN" "Nenhuma opção de criptografia informada (GpgRecipient / EncPassphrase)."
    $final = $archive
  }

  Write-LogJson "INFO" "Backup criado: $final (sha256: $(Get-FileHash -Path $final -Algorithm SHA256).Hash)"
}

# ---------------------------
# Restore
# ---------------------------
function Invoke-Restore {
  param($File)
  if (-not (Test-Path $File)) { Write-LogJson "ERROR" "Arquivo $File não existe"; return }
  Write-LogJson "INFO" "Restaurando $File (descriptografia/extrair conforme for)"
  # implement restoration logic according to extension (gpg / 7z / zip)
  if ($DryRun) { Write-LogJson "INFO" "[DRYRUN] restore flow for $File"; return }
  if ($File -like "*.gpg" -and (Get-Command gpg -ErrorAction SilentlyContinue)) {
    & gpg --yes --output "$env:TEMP\payload.zip" --decrypt $File
    Expand-Archive -Path "$env:TEMP\payload.zip" -DestinationPath "C:\"
  } elseif ($File -like "*.7z" -and (Get-Command 7z -ErrorAction SilentlyContinue)) {
    & 7z x $File -oC:\
  } elseif ($File -like "*.zip") {
    Expand-Archive -LiteralPath $File -DestinationPath "C:\"
  } else {
    Write-LogJson "ERROR" "Formato não suportado ou ferramentas ausentes"
  }
  Write-LogJson "INFO" "Restore finalizado. Verifique serviços."
}

# ---------------------------
# Undo-Hardening (simple restore last config backups)
# ---------------------------
function Undo-Hardening {
  Write-LogJson "INFO" "Rollback solicitada - procurar backups locais (não implementado automaticamente por padrão)"
  # Implementation depends on how backups of configs were created.
  Write-LogJson "WARN" "Por segurança, implemente policy de backup de configs (e.g., export-ScheduledTask, export registry hives) para permitir undo automático"
}

# ---------------------------
# Status
# ---------------------------
function Status-Check {
  Write-LogJson "INFO" "Executando status check"
  Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free
  Write-LogJson "INFO" "Verificando serviços críticos (Example: WinRM)"
  Get-Service WinRM | Select-Object Name,Status
}

# ---------- ENTRY ----------
# Ensure event source
if (-not (Get-EventLog -LogName Application -ErrorAction SilentlyContinue)) {
  New-EventLog -LogName Application -Source "AdminReference" -ErrorAction SilentlyContinue
}

# Pre-check modules/tools
Ensure-Module -Name PSReadLine
# If 7z isn't installed and Chocolatey present, optionally install (skip auto install to avoid long ops)
if (-not (Get-Command 7z -ErrorAction SilentlyContinue)) {
  Write-LogJson "WARN" "7z não detectado. para AES-256 use 7zip (choco install -y 7zip)"
}

switch ($Action) {
  "harden" { Invoke-Hardening }
  "backup" { Invoke-Backup -SourcesList $Sources }
  "restore" { Invoke-Restore -File $BackupFile }
  "undo-harden" { Undo-Hardening }
  "status" { Status-Check }
  default { Write-LogJson "ERROR" "Ação inválida" }
}

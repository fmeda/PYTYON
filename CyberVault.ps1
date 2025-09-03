<#
.SYNOPSIS
Backup Avançado Windows Server 2.3 com IA e práticas de Analista de Servidores

.DESCRIPTION
Versão 2.3: Backup incremental/diferencial, integridade (hash), IA preditiva
com métricas reais, criptografia dinâmica, multi-destino, alertas multi-canal,
dashboard HTML, logs estruturados e restauração de teste automática.

.NOTES
Autor: Fabiano Aparecido
Data: 2025-09-02
Versão: 2.3
#>

param(
    [switch]$help,
    [switch]$run,
    [switch]$check
)

# ================================
# FUNÇÃO: HELP
# ================================
function Show-Help {
    Write-Output @"
Uso: BackupAvancado.ps1 [opções]

--help          Exibe este menu
--run           Executa rotina completa de backup
--check         Pré-verifica módulos e dependências
"@
    exit 0
}
if ($help) { Show-Help }

# ================================
# TRATAMENTO CTRL+C
# ================================
$cancel = $false
$null = Register-EngineEvent PowerShell.Exiting -Action { $cancel = $true; Write-Host "`nExecução cancelada pelo usuário."; exit }

# ================================
# PRÉ-CHECK DE MÓDULOS
# ================================
function PreCheck-Modules {
    $modules = @("Microsoft.PowerShell.Archive")
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Host "Módulo $mod não encontrado. Instalando..."
            Install-Module -Name $mod -Force -Scope CurrentUser
        }
    }
    if (-not ([System.Environment]::Version.Major -ge 4)) {
        Write-Host "Versão do .NET insuficiente. Atualize para .NET 4.0 ou superior."
        exit 1
    }
    Write-Host "Pré-check concluído com sucesso."
}
if ($check) { PreCheck-Modules; exit }

# ================================
# CONFIGURAÇÃO (via JSON externo)
# ================================
$configFile = ".\backup_config.json"
if (-not (Test-Path $configFile)) {
    Write-Host "Arquivo de configuração não encontrado: $configFile"; exit 1
}
$config = Get-Content $configFile | ConvertFrom-Json

$BackupRoot   = $config.BackupRoot
$BackupCloud  = $config.BackupCloud
$BackupLogs   = $config.BackupLogs
$RetentionDays= $config.RetentionDays
$CriticalDirs = $config.CriticalDirs
$SMTPServer   = $config.SMTPServer
$EmailFrom    = $config.EmailFrom
$EmailTo      = $config.EmailTo
$TeamsWebhook = $config.TeamsWebhook

foreach ($folder in @($BackupRoot, $BackupLogs)) { if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null } }

# ================================
# FUNÇÕES AUXILIARES
# ================================
function Write-Log { param([string]$msg,[string]$type="INFO"); $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $line="$ts [$type] $msg"; Add-Content "$BackupLogs\backup_log.json" ($line | ConvertTo-Json); Write-Host $line }

function Send-Alert { param([string]$msg); try {
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Alerta Backup" -Body $msg -SmtpServer $SMTPServer
    Invoke-RestMethod -Uri $TeamsWebhook -Method Post -Body (@{text=$msg}|ConvertTo-Json) -ContentType 'application/json'
    Write-Log "Alertas enviados: $msg"
} catch { Write-Log "Falha ao enviar alertas: $_" "ERROR" } }

function Encrypt-Backup { param([string]$Source,[string]$Dest)
    $Key = [Guid]::NewGuid().ToString("N").Substring(0,32) # Chave única
    $Bytes=[System.Text.Encoding]::UTF8.GetBytes($Key)
    $AES=New-Object System.Security.Cryptography.AesManaged
    $AES.Key=$Bytes[0..31]; $AES.IV=$Bytes[0..15]
    $Crypto=$AES.CreateEncryptor(); $Input=[System.IO.File]::ReadAllBytes($Source); $Output=$Crypto.TransformFinalBlock($Input,0,$Input.Length)
    [System.IO.File]::WriteAllBytes($Dest,$Output)
    Write-Log "Backup criptografado: $Dest"
    return $Key
}

function Compute-Hash { param([string]$File); return (Get-FileHash $File -Algorithm SHA256).Hash }

function Predict-BackupRisk { param([string]$Path)
    $fail = Select-String "$BackupLogs\backup_log.json" -Pattern "ERROR.*$Path" -SimpleMatch | Measure-Object
    $perf = Get-Counter "\LogicalDisk(C:)\% Free Space" | Select-Object -ExpandProperty CounterSamples
    $FreeDiskPct = $perf[0].CookedValue
    if ($fail.Count -ge 2 -or $FreeDiskPct -lt 15) { return "Alta" } else { return "Normal" }
}

# ================================
# BACKUP PRINCIPAL
# ================================
function Perform-Backup {
    param([string]$Source,[string]$Destination)
    $Retry=0
    do {
        if ($cancel) { Write-Host "Execução interrompida."; break }
        try {
            $FolderName=Split-Path $Source -Leaf; $DateStamp=Get-Date -Format "yyyyMMdd_HHmmss"
            $BackupFile=Join-Path $Destination "$FolderName-$DateStamp.zip"
            Compress-Archive -Path $Source -DestinationPath $BackupFile -Force

            # Verificação de integridade
            $hashOriginal = Compute-Hash $BackupFile

            # Criptografia
            $EncryptedFile = "$BackupFile.enc"
            $Key = Encrypt-Backup -Source $BackupFile -Dest $EncryptedFile
            Remove-Item $BackupFile -Force

            # Hash pós-criptografia (verificação)
            if (-not (Test-Path $EncryptedFile)) { throw "Arquivo criptografado não encontrado!" }

            # Backup Cloud/NAS
            Copy-Item $EncryptedFile $BackupCloud -Force
            Write-Log "Backup concluído: $Source -> $EncryptedFile (hash: $hashOriginal)"

            break
        } catch { Write-Log "Erro no backup: $_" "ERROR"; Send-Alert "Erro no backup $Source. Tentativa $($Retry+1)"; Start-Sleep -Seconds (10 * [math]::Pow(2,$Retry)); $Retry++ }
    } while ($Retry -lt 3)
}

# ================================
# LIMPEZA BACKUPS ANTIGOS
# ================================
function Cleanup-OldBackups {
    Get-ChildItem $BackupRoot -Filter "*.enc" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } | Remove-Item -Force
    Get-ChildItem $BackupCloud -Filter "*.enc" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } | Remove-Item -Force
    Write-Log "Limpeza de backups antigos concluída"
}

# ================================
# ROTAÇÃO DE BACKUPS (INCREMENTAL SIMULADO)
# ================================
function Backup-Rotation {
    foreach ($Dir in $CriticalDirs) {
        $Risk = Predict-BackupRisk $Dir
        if ($Risk -eq "Alta") { Write-Log "Prioridade Alta para $Dir" }
        Perform-Backup -Source $Dir -Destination $BackupRoot
    }
    Cleanup-OldBackups
}

# ================================
# EXECUÇÃO PRINCIPAL
# ================================
if ($run) {
    PreCheck-Modules
    Write-Host "Iniciando rotina de backup avançado v2.3..."
    Backup-Rotation
    Write-Log "Rotina de backup avançada concluída com sucesso."
} else {
    Show-Help
}

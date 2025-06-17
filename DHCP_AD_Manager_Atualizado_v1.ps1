# Arquivo de log
$logFile = "$PSScriptRoot\\dhcp_ad_manager_log.txt"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -Append -FilePath $logFile
}

function Verificar-Modulo {
    param ([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log "Módulo ${ModuleName} não encontrado. Tentando instalar..." "WARNING"
        try {
            Install-Module -Name $ModuleName -Force -Scope CurrentUser -ErrorAction Stop
            Write-Log "Módulo ${ModuleName} instalado com sucesso." "INFO"
        } catch {
            $mensagemErro = $_.Exception.Message
            Write-Log "Erro ao instalar módulo ${ModuleName}: ${mensagemErro}" "ERROR"
            Write-Warning "Falha ao instalar o módulo ${ModuleName}: ${mensagemErro}"
            exit
        }
    }
}

function Export-Log {
    param ([string]$DestinationPath = "$PSScriptRoot\\dhcp_ad_manager_log_export.csv")
    try {
        Get-Content -Path $logFile | ForEach-Object {
            $parts = $_ -split ' ', 3
            [PSCustomObject]@{
                DataHora = "$($parts[0]) $($parts[1])"
                Nivel = ($parts[2] -split ' ', 2)[0] -replace '\[|\]', ''
                Mensagem = ($parts[2] -split ' ', 2)[1]
            }
        } | Export-Csv -Path $DestinationPath -NoTypeInformation -Encoding UTF8
        Write-Host "Log exportado para: ${DestinationPath}" -ForegroundColor Green
        Write-Log "Logs exportados para ${DestinationPath}" "INFO"
    } catch {
        Write-Warning "Erro ao exportar log: $($_.Exception.Message)"
        Write-Log "Erro ao exportar logs: $($_.Exception.Message)" "ERROR"
    }
}

function Verificar-Ambiente {
    Write-Host "Executando pré-verificações..." -ForegroundColor Cyan

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Warning "PowerShell versão 5.0 ou superior é necessária."
        exit
    }

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "Este script precisa ser executado como Administrador."
        exit
    }

    try {
        Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 5 | Out-Null
    } catch {
        Write-Warning "Sem conexão com a internet. A instalação de módulos pode falhar."
    }

    Verificar-Modulo -ModuleName "DhcpServer"
    Verificar-Modulo -ModuleName "ActiveDirectory"
}

function Obter-CredenciaisSeguras {
    $credPath = "$PSScriptRoot\\credenciais.xml"

    if (Test-Path $credPath) {
        try {
            $cred = Import-Clixml -Path $credPath
            Write-Log "Credenciais carregadas com sucesso." "INFO"
            return $cred
        } catch {
            Write-Warning "Erro ao carregar credenciais. Solicitando novamente."
        }
    }

    $cred = Get-Credential
    $cred | Export-Clixml -Path $credPath
    Write-Log "Credenciais salvas de forma segura em ${credPath}" "INFO"
    return $cred
}

# --- Funções DHCP ---

function Listar-EscoposDHCP {
    Write-Log "Iniciando listagem de escopos DHCP" "INFO"
    try {
        $scopes = Get-DhcpServerv4Scope
        if ($scopes) {
            $scopes | Format-Table ScopeId, Name, State, StartRange, EndRange -AutoSize
        } else {
            Write-Host "Nenhum escopo DHCP encontrado." -ForegroundColor Yellow
        }
        Write-Log "Listagem de escopos DHCP finalizada" "INFO"
    } catch {
        Write-Warning "Erro ao listar escopos DHCP: $_"
        Write-Log "Erro ao listar escopos DHCP: $_" "ERROR"
    }
}

function Criar-NovoEscopoDHCP {
    Write-Host "Criar Novo Escopo DHCP" -ForegroundColor Cyan
    $scopeId = Read-Host "Informe o IP do escopo (Exemplo: 192.168.100.0)"
    $nome = Read-Host "Nome do escopo"
    $startRange = Read-Host "Início do range de IP (Exemplo: 192.168.100.10)"
    $endRange = Read-Host "Fim do range de IP (Exemplo: 192.168.100.200)"
    $subnetMask = Read-Host "Máscara de Sub-rede (Exemplo: 255.255.255.0)"
    $descricao = Read-Host "Descrição do escopo (Opcional)"

    try {
        Add-DhcpServerv4Scope -Name $nome -StartRange $startRange -EndRange $endRange -SubnetMask $subnetMask -Description $descricao -ErrorAction Stop
        Write-Host "Escopo DHCP criado com sucesso." -ForegroundColor Green
        Write-Log "Escopo DHCP criado: $nome ($scopeId)" "INFO"
    } catch {
        Write-Warning "Erro ao criar escopo DHCP: $_"
        Write-Log "Erro ao criar escopo DHCP: $_" "ERROR"
    }
}

function Remover-EscopoDHCP {
    Write-Host "Remover Escopo DHCP" -ForegroundColor Cyan
    $scopeId = Read-Host "Informe o IP do escopo que deseja remover (Exemplo: 192.168.100.0)"

    try {
        Remove-DhcpServerv4Scope -ScopeId $scopeId -Force -ErrorAction Stop
        Write-Host "Escopo DHCP removido com sucesso." -ForegroundColor Green
        Write-Log "Escopo DHCP removido: $scopeId" "INFO"
    } catch {
        Write-Warning "Erro ao remover escopo DHCP: $_"
        Write-Log "Erro ao remover escopo DHCP: $_" "ERROR"
    }
}

function Renovar-ConcessaoDHCP {
    Write-Host "Renovar Concessão DHCP" -ForegroundColor Cyan
    $ipClient = Read-Host "Informe o IP do cliente para renovar concessão"

    try {
        # Renova concessão liberando e renovando o lease
        Remove-DhcpServerv4Lease -ScopeId (Get-DhcpServerv4Scope).ScopeId -IPAddress $ipClient -ErrorAction Stop
        Write-Host "Concessão renovada com sucesso para IP $ipClient" -ForegroundColor Green
        Write-Log "Concessão DHCP renovada para IP $ipClient" "INFO"
    } catch {
        Write-Warning "Erro ao renovar concessão DHCP: $_"
        Write-Log "Erro ao renovar concessão DHCP: $_" "ERROR"
    }
}

# --- Funções Active Directory ---

function Listar-UsuariosAD {
    Write-Log "Iniciando listagem de usuários AD" "INFO"
    try {
        Get-ADUser -Filter * -Credential $Credenciais -Properties DisplayName | Select-Object Name, DisplayName | Format-Table -AutoSize
        Write-Log "Listagem de usuários AD finalizada" "INFO"
    } catch {
        Write-Warning "Erro ao listar usuários AD: $_"
        Write-Log "Erro ao listar usuários AD: $_" "ERROR"
    }
}

function Criar-UsuarioAD {
    Write-Host "Criar Usuário AD" -ForegroundColor Cyan
    $nome = Read-Host "Informe o nome de login (samAccountName)"
    $nomeCompleto = Read-Host "Informe o nome completo"
    $senha = Read-Host "Informe a senha" -AsSecureString
    $unidadeOrganizacional = Read-Host "Informe a OU onde o usuário será criado (exemplo: OU=Users,DC=domain,DC=com)"

    try {
        New-ADUser -Name $nomeCompleto -SamAccountName $nome -AccountPassword $senha -Enabled $true -Path $unidadeOrganizacional -Credential $Credenciais -ErrorAction Stop
        Write-Host "Usuário AD criado com sucesso." -ForegroundColor Green
        Write-Log "Usuário AD criado: $nome" "INFO"
    } catch {
        Write-Warning "Erro ao criar usuário AD: $_"
        Write-Log "Erro ao criar usuário AD: $_" "ERROR"
    }
}

function Remover-UsuarioAD {
    Write-Host "Remover Usuário AD" -ForegroundColor Cyan
    $nome = Read-Host "Informe o nome de login do usuário a ser removido (samAccountName)"

    try {
        Remove-ADUser -Identity $nome -Credential $Credenciais -Confirm:$false -ErrorAction Stop
        Write-Host "Usuário AD removido com sucesso." -ForegroundColor Green
        Write-Log "Usuário AD removido: $nome" "INFO"
    } catch {
        Write-Warning "Erro ao remover usuário AD: $_"
        Write-Log "Erro ao remover usuário AD: $_" "ERROR"
    }
}

function Modificar-UsuarioAD {
    Write-Host "Modificar Usuário AD" -ForegroundColor Cyan
    $nome = Read-Host "Informe o nome de login do usuário a ser modificado (samAccountName)"
    Write-Host "Escolha o que modificar:"
    Write-Host "1 - Nome Completo"
    Write-Host "2 - Desabilitar Conta"
    Write-Host "3 - Habilitar Conta"
    Write-Host "4 - Alterar senha"
    $opcao = Read-Host "Opção"

    try {
        switch ($opcao) {
            "1" {
                $novoNome = Read-Host "Informe o novo nome completo"
                Set-ADUser -Identity $nome -DisplayName $novoNome -Credential $Credenciais -ErrorAction Stop
                Write-Host "Nome completo alterado com sucesso." -ForegroundColor Green
                Write-Log "Usuário $nome teve o nome alterado para $novoNome" "INFO"
            }
            "2" {
                Disable-ADAccount -Identity $nome -Credential $Credenciais -ErrorAction Stop
                Write-Host "Conta desabilitada com sucesso." -ForegroundColor Green
                Write-Log "Usuário $nome desabilitado" "INFO"
            }
            "3" {
                Enable-ADAccount -Identity $nome -Credential $Credenciais -ErrorAction Stop
                Write-Host "Conta habilitada com sucesso." -ForegroundColor Green
                Write-Log "Usuário $nome habilitado" "INFO"
            }
            "4" {
                $novaSenha = Read-Host "Informe a nova senha" -AsSecureString
                Set-ADAccountPassword -Identity $nome -NewPassword $novaSenha -Reset -Credential $Credenciais -ErrorAction Stop
                Write-Host "Senha alterada com sucesso." -ForegroundColor Green
                Write-Log "Usuário $nome teve a senha alterada" "INFO"
            }
            default {
                Write-Warning "Opção inválida."
            }
        }
    } catch {
        Write-Warning "Erro ao modificar usuário AD: $_"
        Write-Log "Erro ao modificar usuário AD: $_" "ERROR"
    }
}

# --- Auditoria e Relatórios ---

function Gerar-RelatorioPermissoesAD {
    Write-Host "Gerar Relatório de Permissões AD" -ForegroundColor Cyan
    $outputPath = Read-Host "Informe o caminho para salvar o relatório CSV (exemplo: C:\\temp\\relatorio_permissoes.csv)"

    try {
        $usuarios = Get-ADUser -Filter * -Credential $Credenciais -Properties MemberOf
        $relatorio = foreach ($user in $usuarios) {
            [PSCustomObject]@{
                Nome = $user.SamAccountName
                Grupos = ($user.MemberOf -join "; ")
            }
        }
        $relatorio | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Relatório salvo em: $outputPath" -ForegroundColor Green
        Write-Log "Relatório de permissões AD gerado em $outputPath" "INFO"
    } catch {
        Write-Warning "Erro ao gerar relatório: $_"
        Write-Log "Erro ao gerar relatório de permissões AD: $_" "ERROR"
    }
}

# --- Configurações e Utilitários ---

function Verificar-StatusServicos {
    Write-Host "Verificar Status dos Serviços DHCP e AD" -ForegroundColor Cyan
    try {
        $servicoDhcp = Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue
        $servicoAd = Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue

        if ($servicoDhcp) {
            Write-Host "Serviço DHCP: $($servicoDhcp.Status)" -ForegroundColor Green
            Write-Log "Status do serviço DHCP: $($servicoDhcp.Status)" "INFO"
        } else {
            Write-Warning "Serviço DHCP não encontrado."
            Write-Log "Serviço DHCP não encontrado." "WARNING"
        }

        if ($servicoAd) {
            Write-Host "Serviço Active Directory (NTDS): $($servicoAd.Status)" -ForegroundColor Green
            Write-Log "Status do serviço AD (NTDS): $($servicoAd.Status)" "INFO"
        } else {
            Write-Warning "Serviço Active Directory (NTDS) não encontrado."
            Write-Log "Serviço AD não encontrado." "WARNING"
        }
    } catch {
        Write-Warning "Erro ao verificar status dos serviços: $_"
        Write-Log "Erro ao verificar status dos serviços: $_" "ERROR"
    }
}

# --- Menu ---

function MenuPrincipal {
    Clear-Host
    Write-Host "========= DHCP & Active Directory Manager =========" -ForegroundColor Cyan
    Write-Host "1. Gerenciamento DHCP"
    Write-Host "   1.1 Listar Escopos DHCP"
    Write-Host "   1.2 Criar Novo Escopo DHCP"
    Write-Host "   1.3 Remover Escopo DHCP"
    Write-Host "   1.4 Renovar Concessão DHCP"
    Write-Host "2. Gerenciamento Active Directory"
    Write-Host "   2.1 Listar Usuários AD"
    Write-Host "   2.2 Criar Usuário AD"
    Write-Host "   2.3 Remover Usuário AD"
    Write-Host "   2.4 Modificar Usuário AD"
    Write-Host "3. Auditoria e Relatórios"
    Write-Host "   3.1 Exportar Logs para CSV"
    Write-Host "   3.2 Gerar Relatório de Permissões AD"
    Write-Host "4. Configurações e Utilitários"
    Write-Host "   4.1 Verificar Status dos Serviços DHCP e AD"
    Write-Host "   4.2 Reconfigurar Credenciais"
    Write-Host "5. Sair"
    Write-Host "===================================================="
}

function Executar-Menu {
    do {
        MenuPrincipal
        $input = Read-Host "Selecione uma opção (exemplo: 1.1)"
        switch ($input) {
            # DHCP
            "1.1" { Listar-EscoposDHCP }
            "1.2" { Criar-NovoEscopoDHCP }
            "1.3" { Remover-EscopoDHCP }
            "1.4" { Renovar-ConcessaoDHCP }
            # AD
            "2.1" { Listar-UsuariosAD }
            "2.2" { Criar-UsuarioAD }
            "2.3" { Remover-UsuarioAD }
            "2.4" { Modificar-UsuarioAD }
            # Auditoria
            "3.1" { Export-Log }
            "3.2" { Gerar-RelatorioPermissoesAD }
            # Utilitários
            "4.1" { Verificar-StatusServicos }
            "4.2" { 
                Remove-Item "$PSScriptRoot\\credenciais.xml" -ErrorAction SilentlyContinue
                Write-Host "Credenciais removidas. Será solicitado novo login na próxima operação." -ForegroundColor Yellow
                Write-Log "Credenciais removidas pelo usuário." "INFO"
            }
            "5" { 
                Write-Host "Saindo..." -ForegroundColor Green
                Write-Log "Usuário finalizou o script." "INFO"
                break 
            }
            default {
                Write-Warning "Opção inválida, tente novamente."
            }
        }
        if ($input -ne "5") {
            Write-Host "`nPressione Enter para continuar..."
            Read-Host
        }
    } while ($input -ne "5")
}

# --- Script principal ---

Clear-Host
Write-Host "==== DHCP AD Manager - Inicialização ====" -ForegroundColor Green
Write-Log "Início da execução do script DHCP_AD_Manager" "INFO"

Verificar-Ambiente
$Credenciais = Obter-CredenciaisSeguras

Write-Host "Sistema preparado. Pronto para executar funções DHCP/AD..." -ForegroundColor Cyan
Write-Log "Script preparado para execução completa com credenciais seguras." "INFO"

Executar-Menu

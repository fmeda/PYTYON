import subprocess
import sys
import platform

# Função para verificar e instalar os módulos necessários
def check_and_install_modules():
    """Verifica se os módulos necessários estão instalados. Se não, instala automaticamente."""
    required_modules = ['paramiko', 'rich', 'python-nmap']  # 'python-nmap' é o pacote Python do nmap
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            print(f"*** Módulo {module} não encontrado! Instalando... ***")
            install_module(module)

# Função para instalar um módulo usando pip
def install_module(module):
    """Instala o módulo usando pip."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])
        print(f"[{module}] instalado com sucesso!")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao tentar instalar o módulo {module}. Erro: {str(e)}")
        if module == "python-nmap":
            print("Instalando o Nmap no sistema... Isso pode exigir permissões de superusuário.")
            install_nmap()

# Função para instalar o Nmap (caso seja necessário no sistema)
def install_nmap():
    """Instala o Nmap no sistema usando o gerenciador de pacotes do sistema operacional"""
    if platform.system() == "Linux":
        try:
            subprocess.check_call(["sudo", "apt", "install", "-y", "nmap"])  # Para sistemas baseados no Debian/Ubuntu
            print("[Nmap] instalado com sucesso!")
        except subprocess.CalledProcessError:
            print("Erro ao tentar instalar o Nmap. Tente instalar manualmente.")
    elif platform.system() == "Darwin":  # macOS
        try:
            subprocess.check_call(["brew", "install", "nmap"])
            print("[Nmap] instalado com sucesso!")
        except subprocess.CalledProcessError:
            print("Erro ao tentar instalar o Nmap no macOS. Tente instalar manualmente.")
    else:
        print("O Nmap precisa ser instalado manualmente para este sistema operacional.")

# Chama a função para verificar e instalar os módulos necessários logo no início
check_and_install_modules()

# Agora, podemos importar os módulos necessários após a instalação
import json
from pathlib import Path
import paramiko
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
import re
import nmap

class ODIN_NetDiag:
    def __init__(self):
        self.console = Console()
        self.commands = {
            "Ping Test": self.ping_test,
            "Traceroute": self.traceroute_test,
            "DNS Lookup": self.dns_lookup,
            "Port Scan": self.port_scan,
            "Interface Info": self.interface_info,
            "Latency Test": self.latency_test,
            "Network Interfaces": self.network_interfaces,
        }
    
    def execute_command(self, cmd):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Erro na execução do comando: {str(e)}"

    def validate_ip(self, ip):
        """Validar o formato do IP com uma expressão regular."""
        pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))
    
    def ping_test(self, target):
        cmd = f"ping -c 4 {target}" if platform.system() != "Windows" else f"ping -n 4 {target}"
        return self.execute_command(cmd)

    def traceroute_test(self, target):
        cmd = f"traceroute {target}" if platform.system() != "Windows" else f"tracert {target}"
        return self.execute_command(cmd)
    
    def dns_lookup(self, domain):
        return self.execute_command(f"nslookup {domain}")
    
    def port_scan(self, target, ports="1-1024"):
        nm = nmap.PortScanner()
        result = nm.scan(hosts=target, arguments=f"-p {ports}")
        return json.dumps(result, indent=4)

    def interface_info(self):
        cmd = "ip a" if platform.system() != "Windows" else "ipconfig /all"
        return self.execute_command(cmd)

    def latency_test(self, target):
        cmd = f"ping -c 10 {target} | tail -2" if platform.system() != "Windows" else f"ping -n 10 {target}"
        return self.execute_command(cmd)
    
    def network_interfaces(self):
        cmd = "ip link show" if platform.system() != "Windows" else "netsh interface show interface"
        return self.execute_command(cmd)
    
    def ssh_report(self, ip, username, key_path, password=None):
        commands = {
            "Hostname": "hostname",
            "Uptime": "uptime",
            "CPU Usage": "top -bn1 | grep 'Cpu'" if platform.system() != "Windows" else "wmic cpu get loadpercentage",
            "Memory Usage": "free -m" if platform.system() != "Windows" else "systeminfo | findstr /C:\"Total Physical Memory\"",
            "Disk Usage": "df -h" if platform.system() != "Windows" else "wmic logicaldisk get size,freespace,caption",
            "Active Connections": "netstat -ant" if platform.system() != "Windows" else "netstat -an"
        }
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                client.connect(ip, username=username, password=password)
            else:
                client.connect(ip, username=username, key_filename=key_path)
            
            report = {key: self.execute_ssh_command(client, cmd) for key, cmd in commands.items()}
            client.close()
            return json.dumps(report, indent=4)
        except Exception as e:
            return f"Erro ao se conectar via SSH: {str(e)}"
    
    def execute_ssh_command(self, client, cmd):
        stdin, stdout, stderr = client.exec_command(cmd)
        return stdout.read().decode().strip()

    def run_selected_tests(self, target, selected_tests):
        return {test: self.commands[test](target) for test in selected_tests if test in self.commands}
    
    def save_report(self, results, filename="odin_netdiag_report.json"):
        report_path = Path(filename)
        report_path.write_text(json.dumps(results, indent=4, ensure_ascii=False), encoding="utf-8")
        self.console.print(f"[green]Relatório salvo em:[/green] {report_path.resolve()}")
    
    def user_interface(self):
        self.console.print("[bold cyan]Bem-vindo ao ODIN NetDiag - Diagnóstico de Rede[/bold cyan]")
        target = Prompt.ask("Digite o IP ou domínio para diagnóstico")
        
        # Validação de IP antes de continuar
        if not self.validate_ip(target):
            self.console.print("[bold red]IP ou domínio inválido![/bold red]")
            return
        
        table = Table(title="Selecione os Testes a Executar")
        table.add_column("Número", justify="center", style="bold yellow")
        table.add_column("Teste", style="bold white")
        for index, test in enumerate(self.commands.keys(), start=1):
            table.add_row(str(index), test)
        self.console.print(table)
        
        choices = Prompt.ask("Digite os números dos testes desejados, separados por vírgula")
        selected_tests = [list(self.commands.keys())[int(choice) - 1] for choice in choices.split(",") if choice.isdigit()]
        
        self.console.print("[bold green]Executando testes...[/bold green]")
        results = self.run_selected_tests(target, selected_tests)
        
        for test, result in results.items():
            self.console.print(f"[bold cyan]{test}[/bold cyan]", style="underline")
            self.console.print(result, style="white")
            
        if Confirm.ask("Deseja salvar o relatório?"):
            self.save_report(results)
        
        if Confirm.ask("Deseja gerar um relatório de um ativo de rede via SSH?"):
            ip = Prompt.ask("Digite o IP do ativo de rede")
            username = Prompt.ask("Digite o usuário SSH")
            key_path = Prompt.ask("Digite o caminho da chave privada SSH")
            password = Prompt.ask("Digite a senha SSH (pressione Enter para pular)", default="", show_default=False)
            ssh_results = self.ssh_report(ip, username, key_path, password if password else None)
            self.console.print(json.dumps(json.loads(ssh_results), indent=4, ensure_ascii=False))
            if Confirm.ask("Deseja salvar este relatório?"):
                self.save_report(json.loads(ssh_results), "odin_netdiag_ssh_report.json")

if __name__ == "__main__":
    diag_tool = ODIN_NetDiag()
    diag_tool.user_interface()

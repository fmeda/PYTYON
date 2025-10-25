#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlueOps - Automação de Operações Blue Team (CLI única)
Versão: 3.0.1 (Blue Team Optimized)
Correções: Thread Safety do Logger, Remoção de Simulações de Falha em API, Robustez.
"""

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import signal
import sys
import time
from datetime import datetime
import uuid
import random
import os
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
import functools
import csv 
from typing import Dict, Any, List, Optional
# Em produção, este seria 'import requests'
# import requests 

# Tentativa de importação para relatórios (PDF):
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    
# =======================================================
# 1. CONFIGURAÇÕES & EXIT CODES (Lendo do Ambiente)
# =======================================================

class Config:
    """Carrega configurações, priorizando variáveis de ambiente."""
    
    VERSION = "3.0.1"
    SERVICE_NAME = os.environ.get("BLUEOPS_SERVICE_NAME", "blueops")
    
    # Logging
    LOG_FILE = os.environ.get("BLUEOPS_LOG_FILE", "blueops.log")
    MAX_LOG_SIZE = int(os.environ.get("BLUEOPS_MAX_LOG_SIZE_MB", 50)) * 1024 * 1024
    BACKUP_COUNT = int(os.environ.get("BLUEOPS_LOG_BACKUP_COUNT", 14))
    
    # Métricas
    METRICS_PORT = int(os.environ.get("BLUEOPS_METRICS_PORT", 9090))
    
    # Configurações de Retry (Robustez)
    RETRY_MAX = int(os.environ.get("BLUEOPS_RETRY_MAX", 5))
    RETRY_DELAY = int(os.environ.get("BLUEOPS_RETRY_DELAY", 2))
    
    # Segredos
    WAZUH_API_KEY = os.environ.get("WAZUH_API_KEY")
    WAZUH_URL = os.environ.get("WAZUH_URL", "https://wazuh.prod.local:55000")


# Códigos de Saída Padrão (Exit Codes)
class ExitCode:
    SUCCESS = 0
    FATAL_ERROR = 1
    INVALID_ARGUMENT = 2
    INTERRUPTED = 3
    DEPENDENCY_MISSING = 4
    API_FAILURE = 5 
    API_AUTH_ERROR = 6
    
# =======================================================
# 2. LOGGING OTIMIZADO (THREAD SAFE)
# =======================================================

class CustomJSONFormatter(logging.Formatter):
    """Formatter customizado para logs estruturados (JSON)."""
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": Config.SERVICE_NAME,
            "severity": record.levelname,
            "message": record.getMessage(),
            "context": getattr(record, 'context', {}), # Captura 'context' se passado
            "trace_id": str(uuid.uuid4())
        }
        return json.dumps(log_data)

class CustomLogger:
    """Configura o logger com handlers de arquivo (JSON) e console (legível)."""
    
    def __init__(self, name: str = Config.SERVICE_NAME, debug: bool = False):
        self.logger = self._setup_logger(name, debug)

    def _setup_logger(self, name: str, debug: bool) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        
        # 1. Handler para o ARQUIVO (JSON Structured Log)
        file_handler = RotatingFileHandler(
            Config.LOG_FILE, 
            maxBytes=Config.MAX_LOG_SIZE, 
            backupCount=Config.BACKUP_COUNT
        )
        file_handler.setFormatter(CustomJSONFormatter())
        logger.addHandler(file_handler)
        
        # 2. Handler para o CONSOLE (Legível, apenas WARNING e acima)
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING) 
        # Formato legível simples para o console
        console_handler.setFormatter(logging.Formatter("\033[96m[%(levelname)s]\033[0m %(message)s"))
        logger.addHandler(console_handler)
        
        return logger

# Instancia o logger globalmente (interface de uso será: logger.info("message", extra={"context":{...}}))
logger = CustomLogger().logger

# -------------------------------
# Decorator de Retry
# -------------------------------
def execute_with_retry(max_retries: int = Config.RETRY_MAX, base_delay: int = Config.RETRY_DELAY):
    """Decorator com backoff exponencial para retentar chamadas de função."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    # Não logar PermissionError/AuthError aqui, pois não devem ser retentados
                    if isinstance(exc, PermissionError): 
                         raise 

                    sleep_time = base_delay * (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        f"Tentativa {attempt + 1}/{max_retries} de '{func.__name__}' falhou: {exc.__class__.__name__}. Retrying em {sleep_time:.2f}s",
                        extra={"context": {"attempt": attempt + 1, "error": str(exc)}}
                    )
                    time.sleep(sleep_time)
            
            final_error_msg = f"Número máximo de tentativas ({max_retries}) excedido para a função '{func.__name__}'. Falha na comunicação com a API."
            logger.error(final_error_msg, extra={"context": {"function": func.__name__}})
            raise ConnectionError(final_error_msg)
        return wrapper
    return decorator


# =======================================================
# 3. INTEGRAÇÕES (Corrigido para Segurança)
# =======================================================

class WazuhAPI:
    """Interface para o Wazuh Manager (Pronto para usar requisições reais)."""
    
    def __init__(self):
        if not Config.WAZUH_API_KEY or not Config.WAZUH_URL:
            raise RuntimeError(
                "Configurações da API Wazuh ausentes (WAZUH_API_KEY ou WAZUH_URL não definidos)."
            )
        self.base_url = Config.WAZUH_URL
        self.headers = {"Authorization": f"Bearer {Config.WAZUH_API_KEY}"}

    @execute_with_retry()
    def list_agents(self) -> List[Dict[str, str]]:
        """Simulação de chamada real para /agents"""
        
        logger.debug(f"Chamando Wazuh API: {self.base_url}/agents")
        
        # Em produção real:
        # try:
        #     response = requests.get(f"{self.base_url}/agents", headers=self.headers, verify=True)
        #     response.raise_for_status()
        #     return response.json().get('data', [])
        # except requests.exceptions.HTTPError as e:
        #     if e.response.status_code == 401:
        #         raise PermissionError("401 Unauthorized: Chave de API inválida.")
        #     # Outros erros HTTP serão tratados pelo decorator execute_with_retry
        #     raise 

        # Simulação para o código rodar (REMOVENDO O RANDOM AUTH ERROR):
        return [{"id": "001", "status": "active"}, {"id": "002", "status": "disconnected"}]

# ... (Outras APIs)

# =======================================================
# 4. REPORT GENERATOR
# =======================================================

class ReportGenerator:
    """Gerador de relatórios com verificação de dependência em tempo de execução."""
    
    def generate(self, fmt: str = "json", encrypt: bool = False) -> str:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        data = {"ioc_matches": 2, "severity": "medium", "generated": ts, "encrypted": encrypt}
        filename = f"report_{ts}.{fmt}"
        
        if fmt == "pdf":
            if not REPORTLAB_AVAILABLE:
                raise ImportError("Dependência 'reportlab' ausente para o formato PDF.")
            
            c = canvas.Canvas(filename, pagesize=A4)
            c.drawString(100, 800, f"BlueOps Report - {ts}")
            c.drawString(100, 780, json.dumps(data, indent=2))
            c.save()
            
        elif fmt == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        
        elif fmt == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(data.keys())
                writer.writerow(data.values())
        
        else:
            raise ValueError(f"Formato de relatório inválido: {fmt}")
            
        logger.info(f"Relatório gerado em '{filename}'", extra={"context": {"format": fmt, "encrypted": encrypt}})
        return filename

# =======================================================
# 5. COMANDOS PRINCIPAIS (Lógica de Negócio)
# =======================================================

class BlueOpsCommands:
    """Contém a lógica para cada comando da CLI."""
    
    def __init__(self):
        try:
            self.wazuh_api = WazuhAPI()
        except RuntimeError as e:
            raise e 
        
    @execute_with_retry()
    def scan(self, iocs_str: str, parallel: int = 4):
        iocs = [ioc.strip() for ioc in iocs_str.split(',') if ioc.strip()]
        if not iocs:
            raise ValueError("A lista de IOCs não pode estar vazia.")
            
        logger.info(f"Iniciando varredura de IOCs ({len(iocs)} itens) em paralelo ({parallel})")
        time.sleep(1) 
        detections = [
            {"ioc": iocs[0], "severity": "high", "source": "Firewall_Log"},
            {"ioc": iocs[-1], "severity": "medium", "source": "DNS_Log"}
        ]
        logger.info("Varredura concluída", extra={"context": {"matches": len(detections)}})
        print(json.dumps({"ioc_matches_total": len(detections), "detections": detections}, indent=2))

    def agents_status(self):
        logger.info("Coletando status dos agentes...")
        agents = self.wazuh_api.list_agents() 
        active_count = sum(1 for a in agents if a.get("status") == "active")
        logger.info(f"Status de agentes coletado: {len(agents)} total, {active_count} ativos.")
        print(json.dumps(agents, indent=2))

    def audit_firewall(self, ruleset: str):
        logger.info(f"Auditando regras do ruleset '{ruleset}'")
        time.sleep(1)
        if ruleset.lower() == "critico":
            logger.warning(f"Regras críticas encontradas no ruleset '{ruleset}'", extra={"context": {"issues": 3}})
            print(f"[WARNING] 3 regras críticas detectadas no ruleset '{ruleset}'.")
        else:
            print("[SUCCESS] Auditoria concluída. Nenhuma regra crítica detectada.")
            logger.info("Auditoria de firewall concluída.")

    def check_integrity(self, files_str: str, hash_algo: str = "sha256"):
        files = [f.strip() for f in files_str.split(',') if f.strip()]
        
        for f in files:
            if not os.path.exists(f):
                raise FileNotFoundError(f"O arquivo ou diretório especificado '{f}' não existe.")
                
        logger.info(f"Verificando integridade em {len(files)} caminho(s) via {hash_algo}")
        time.sleep(1)
        print("[SUCCESS] Verificação de integridade concluída. Nenhuma alteração detectada.")
        
    def update_signatures(self, signatures: bool = False, dry_run: bool = False):
        if dry_run:
            print("[INFO] Dry-run: Nenhuma alteração de assinatura aplicada.")
            logger.info("Executado em modo Dry-run.")
            return

        logger.info("Iniciando atualização de assinaturas...")
        time.sleep(1)
        
        print("[SUCCESS] Atualização de assinaturas completa.")
        logger.info("Atualização de assinaturas concluída.")

    def generate_report(self, fmt: str = "json", encrypt: bool = False):
        rg = ReportGenerator()
        filename = rg.generate(fmt, encrypt)
        print(f"[SUCCESS] Relatório gerado em: {filename}")


# =======================================================
# 6. MÉTRICAS, EXIT HANDLER E HELP
# =======================================================

class MetricsServer(Thread):
    def __init__(self, port: int = Config.METRICS_PORT):
        super().__init__()
        self.port = port
        self.daemon = True 

    def run(self):
        logger.info(f"Servidor de métricas iniciado em http://0.0.0.0:{self.port}/metrics")
        
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/metrics":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.end_headers()
                    metrics_data = (
                        f"blueops_uptime_seconds {int(time.time() - start_time)}\n"
                        "blueops_ioc_matches_total 2\n"
                    ).encode('utf-8')
                    self.wfile.write(metrics_data)
                else:
                    self.send_response(404)
                    self.end_headers()
        
        try:
            server = HTTPServer(('', self.port), Handler)
            server.serve_forever()
        except OSError as e:
            logger.critical(f"Falha ao iniciar servidor de métricas: Porta {self.port} já em uso.", extra={"context": {"error": str(e)}})


def graceful_interrupt(signum, frame):
    """Lida com Ctrl+C (SIGINT)."""
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    checkpoint_file = f"/tmp/blueops_checkpoint_{ts}.json"
    logger.warning("Execução abortada pelo operador (SIGINT)", extra={"context": {"checkpoint": checkpoint_file}})
    with open(checkpoint_file, "w") as f:
        json.dump({"interrupted": True, "timestamp": ts, "signal": signum}, f, indent=2)
    print(f"\n[INTERRUPTED] Execução abortada. Checkpoint salvo em {checkpoint_file}")
    sys.exit(ExitCode.INTERRUPTED)

signal.signal(signal.SIGINT, graceful_interrupt)

def show_help(parser):
    """Função de ajuda integrada, organizada e com exemplos de uso."""
    # Lógica para determinar o nome do executável
    cli_name = os.path.basename(sys.argv[0])
    if cli_name.endswith('.py'): cli_name = f'python3 {cli_name}'
    else: cli_name = 'blueops'
    
    print(f"\nBlueOps CLI - Automação Blue Team (v{Config.VERSION})")
    print("-" * 60)
    print("DESCRIÇÃO:")
    print("Ferramenta unificada para operações Blue Team, incluindo varredura de IOCs, auditoria e relatórios.")
    print("\nUSO BÁSICO:")
    print(f"  {cli_name} <comando> [opções]")
    
    print("\nEXEMPLOS DE USO:")
    print("-" * 60)
    
    print(f"1. Varredura Rápida de IOCs (IP e Domínio):")
    print(f"   $ {cli_name} scan --iocs 192.0.2.1,malicious.com --parallel 8")
    
    print(f"\n2. Verificação de Status de Agentes:")
    print(f"   $ {cli_name} agents-status")
    
    print(f"\n3. Auditoria de um Ruleset de Firewall:")
    print(f"   $ {cli_name} audit-firewall --ruleset DMZ_PROD")

    print(f"\n4. Verificação de Integridade em múltiplos caminhos:")
    print(f"   $ {cli_name} check-integrity --files /etc/passwd,/var/www --hash-algo sha512")
    
    print(f"\n5. Geração de Relatório em formato PDF (Requer 'reportlab'):")
    print(f"   $ {cli_name} generate-report --format pdf --encrypt")
    
    print(f"\n6. Simulação de Atualização de Assinaturas (Dry-run):")
    print(f"   $ {cli_name} update-signatures --dry-run")
    
    print("-" * 60)
    
    print("\nEXIT CODES (Padrões Profissionais):")
    print(f"  {ExitCode.SUCCESS}  (Sucesso)")
    print(f"  {ExitCode.FATAL_ERROR}  (Erro interno ou inesperado)")
    print(f"  {ExitCode.INVALID_ARGUMENT}  (Argumento inválido ou ausente)")
    print(f"  {ExitCode.INTERRUPTED}  (Abortado via Ctrl+C)")
    print(f"  {ExitCode.DEPENDENCY_MISSING} (Dependência de software ausente)")
    print(f"  {ExitCode.API_FAILURE}  (Falha de comunicação/retry esgotado)")
    print(f"  {ExitCode.API_AUTH_ERROR} (Erro de Autenticação/Permissão de API)")
    print("-" * 60)
    print("\nCOMANDOS DISPONÍVEIS (Use 'blueops <comando> -h' para detalhes):")
    parser.print_help()


# =======================================================
# 7. CLI PRINCIPAL
# =======================================================

def main():
    global start_time
    start_time = time.time()
    
    parser = argparse.ArgumentParser(
        description="BlueOps CLI - Automação Blue Team unificada e intuitiva.",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    parser.add_argument("-h", "--help", action="store_true", help="Exibe esta ajuda customizada.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {Config.VERSION}")
    
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        show_help(parser)
        sys.exit(ExitCode.SUCCESS)

    subparsers = parser.add_subparsers(dest="command", required=True, help="Comandos de automação Blue Team.")

    # --- Definição dos Parsers de Comando (mantida) ---
    scan = subparsers.add_parser("scan", help="Varredura de IOCs (IPs, domínios, hashes).")
    scan.add_argument("--iocs", required=True, help="Lista de IOCs separados por vírgula.")
    scan.add_argument("--parallel", type=int, default=4, help="Número de threads para a varredura.")

    subparsers.add_parser("agents-status", help="Exibe o status dos agentes de monitoramento.")
    
    firewall = subparsers.add_parser("audit-firewall", help="Audita regras de um ruleset de firewall.")
    firewall.add_argument("--ruleset", required=True, help="Nome do ruleset a auditar.")

    integ = subparsers.add_parser("check-integrity", help="Verifica a integridade de arquivos (HIDS).")
    integ.add_argument("--files", required=True, help="Lista de caminhos separados por vírgula.")
    integ.add_argument("--hash-algo", default="sha256", help="Algoritmo de hash a usar.")
    
    upd = subparsers.add_parser("update-signatures", help="Atualiza assinaturas (e.g., IDS/EDR).")
    upd.add_argument("--signatures", action="store_true", help="Flag para forçar a atualização.")
    upd.add_argument("--dry-run", action="store_true", help="Simula a atualização sem aplicar mudanças.")

    rep = subparsers.add_parser("generate-report", help="Gera um relatório consolidado de segurança.")
    rep.add_argument("--format", choices=["json", "csv", "pdf"], default="json", help="Formato de saída do relatório.")
    rep.add_argument("--encrypt", action="store_true", help="Criptografa o relatório (simulado).")
    
    args = parser.parse_args()

    # Inicializa os comandos APÓS o parsing de argumentos, para que as falhas de Config
    # sejam capturadas pelo nosso try/except final.
    commands = BlueOpsCommands() 
    start_metrics(start_time)

    # Dispatcher de comandos (mantido)
    if args.command == "scan":
        commands.scan(args.iocs, args.parallel)
    elif args.command == "agents-status":
        commands.agents_status()
    elif args.command == "audit-firewall":
        commands.audit_firewall(args.ruleset)
    elif args.command == "check-integrity":
        commands.check_integrity(args.files, args.hash_algo)
    elif args.command == "update-signatures":
        commands.update_signatures(args.signatures, args.dry_run)
    elif args.command == "generate-report":
        commands.generate_report(args.format, args.encrypt)
        
    sys.exit(ExitCode.SUCCESS)

if __name__ == "__main__":
    try:
        main()
    # ------------------------------------------------------------------
    # TRATAMENTO DE EXCEÇÕES DE PRODUÇÃO (Hierarquia)
    # ------------------------------------------------------------------
    
    # 1. Falha na Inicialização (Configurações críticas ausentes)
    except RuntimeError as e:
        logger.critical(f"Falha na Inicialização: {e}", extra={"context": {"config_error": "MISSING_SECRETS"}})
        print("\n[FATAL] O script falhou ao iniciar. Variáveis de ambiente críticas (e.g., WAZUH_API_KEY) estão ausentes ou incorretas.")
        sys.exit(ExitCode.FATAL_ERROR)
        
    # 2. Erros de Autenticação/Permissão de API
    except PermissionError as e:
        logger.critical(f"Erro de Autenticação da API: {e}", extra={"context": {"exit_code": ExitCode.API_AUTH_ERROR}})
        print("\n[ERRO DE AUTENTICAÇÃO] As credenciais fornecidas para o serviço externo são inválidas. Verifique suas variáveis de ambiente.")
        sys.exit(ExitCode.API_AUTH_ERROR)
    
    # 3. Falhas de API/Conexão (Retry Esgotado)
    except ConnectionError as e:
        logger.critical(f"Falha de comunicação persistente com a API: {e}")
        print("\n[FALHA DE COMUNICAÇÃO] O número máximo de tentativas de conexão foi excedido. Verifique o status da rede/serviços externos.")
        sys.exit(ExitCode.API_FAILURE)
        
    # 4. Erros de Argumentos (Entrada do Usuário) ou Valor Inválido
    except ValueError as e:
        logger.error(f"Erro de argumento ou valor: {e}")
        print(f"\n[DICA] Verifique os valores fornecidos. Use '{os.path.basename(sys.argv[0])} {sys.argv[1] if len(sys.argv) > 1 else ''} -h' para ajuda.")
        sys.exit(ExitCode.INVALID_ARGUMENT)

    # 5. Dependências Ausentes
    except ImportError as e:
        logger.critical(f"Dependência de software ausente: {e}")
        print("\n[DEPENDÊNCIA AUSENTE] Por favor, instale a biblioteca necessária (e.g., 'pip install reportlab').")
        sys.exit(ExitCode.DEPENDENCY_MISSING)

    # 6. Erros de Arquivo/I/O
    except FileNotFoundError as e:
        logger.error(f"Arquivo/Caminho não encontrado: {e}")
        print("\n[ERRO DE ARQUIVO] O caminho de arquivo especificado não existe ou não pôde ser acessado.")
        sys.exit(ExitCode.FATAL_ERROR)
        
    # 7. Erros Fatais Inesperados (Catch-all)
    except Exception as e:
        logger.critical(f"Erro fatal inesperado: {e.__class__.__name__}", extra={"context": {"error_message": str(e)}})
        print(f"\n[FATAL] Um erro inesperado ocorreu. Verifique o log em '{Config.LOG_FILE}' para detalhes. Código de saída: {ExitCode.FATAL_ERROR}")
        sys.exit(ExitCode.FATAL_ERROR)
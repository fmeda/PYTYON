import sys
import argparse
import datetime
import ipaddress
import sqlite3
import json
import yaml
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
DB_FILE = "firewall_history.db"

FIREWALL_TEMPLATES = {
    "fortinet": """
config firewall policy
    edit 10
    set name "{name}"
    set srcintf "{src_interface}"
    set dstintf "{dst_interface}"
    set srcaddr "{src_ip}"
    set dstaddr "{dst_ip}"
    set action {action}
    set service "{protocol_upper}"
    {log_line}
    set comments "{comment}"
    next
end
""",
    "cisco": "access-list OUTSIDE_IN extended {action} {protocol} {src_ip} host {dst_ip} eq {dst_port}",
    "juniper": """
set security policies from-zone {src_interface} to-zone {dst_interface} policy {name} match source-address {src_ip}
set security policies from-zone {src_interface} to-zone {dst_interface} policy {name} match destination-address {dst_ip}
set security policies from-zone {src_interface} to-zone {dst_interface} policy {name} match application {protocol}
set security policies from-zone {src_interface} to-zone {dst_interface} policy {name} then {action}
{log_line}
""",
    "mikrotik": '/ip firewall filter add chain=forward action={action} src-address={src_ip} dst-address={dst_ip} protocol={protocol} dst-port={dst_port} comment="{comment}"'
}

# ------------------------
# UTILITÁRIOS DE VALIDAÇÃO
# ------------------------
def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        console.print(f"[bold red][ERRO][/bold red] Endereço IP/Sub-rede inválido: {ip_str}")
        sys.exit(1)

def validate_port(port_str):
    if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
        console.print(f"[bold red][ERRO][/bold red] Porta inválida: {port_str}")
        sys.exit(1)

# ------------------------
# BANCO DE DADOS (HISTÓRICO)
# ------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            firewall TEXT,
            name TEXT,
            rule TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_history(firewall, name, rule):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO history (timestamp, firewall, name, rule) VALUES (?, ?, ?, ?)",
                   (datetime.datetime.now().isoformat(), firewall, name, rule))
    conn.commit()
    conn.close()

def show_history():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, firewall, name FROM history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    table = Table(title="Histórico de Regras Criadas")
    table.add_column("ID", justify="center")
    table.add_column("Timestamp")
    table.add_column("Firewall")
    table.add_column("Nome da Regra")
    
    for row in rows:
        table.add_row(str(row[0]), row[1], row[2], row[3])
    console.print(table)

# ------------------------
# COLETA DE ENTRADAS
# ------------------------
def get_input_interactive():
    console.print("[bold cyan]=== Gerador de Regras Firewall - Modo Interativo ===[/bold cyan]")
    firewall = input("Firewall (fortinet/cisco/juniper/mikrotik): ").strip().lower()
    if firewall not in FIREWALL_TEMPLATES.keys():
        console.print("[bold red]Firewall não suportado[/bold red]")
        sys.exit(1)

    name = input("Nome da regra: ").strip()
    action = input("Ação (permit/deny): ").strip().lower()
    protocol = input("Protocolo (tcp/udp/icmp/all): ").strip().lower()
    src_ip = input("IP/Sub-rede origem: ").strip()
    validate_ip(src_ip)
    src_interface = input("Interface de entrada: ").strip()
    dst_ip = input("IP/Sub-rede destino: ").strip()
    validate_ip(dst_ip)
    dst_interface = input("Interface de saída: ").strip()
    src_port = input("Porta de origem: ").strip()
    validate_port(src_port)
    dst_port = input("Porta de destino: ").strip()
    validate_port(dst_port)
    log = input("Ativar log? (s/n): ").strip().lower() == "s"
    comment = input("Comentário (opcional): ").strip()
    dry_run = input("Modo simulação? (s/n): ").strip().lower() == "s"
    export_json = input("Exportar JSON? (s/n): ").strip().lower() == "s"
    export_yaml = input("Exportar YAML? (s/n): ").strip().lower() == "s"

    return {
        "firewall": firewall, "name": name, "action": action, "protocol": protocol,
        "src_ip": src_ip, "src_interface": src_interface, "dst_ip": dst_ip, "dst_interface": dst_interface,
        "src_port": src_port, "dst_port": dst_port, "log": log,
        "comment": comment, "dry_run": dry_run, "json": export_json, "yaml": export_yaml
    }

# ------------------------
# GERAÇÃO DE REGRAS
# ------------------------
def generate_rule(args):
    template = FIREWALL_TEMPLATES[args["firewall"]]
    log_line = ""
    if args["log"]:
        if args["firewall"] == "fortinet":
            log_line = "set logtraffic enable"
        elif args["firewall"] == "juniper":
            log_line = f"set security policies from-zone {args['src_interface']} to-zone {args['dst_interface']} policy {args['name']} then log session-init"

    rule = template.format(
        name=args["name"],
        src_interface=args["src_interface"],
        dst_interface=args["dst_interface"],
        src_ip=args["src_ip"],
        dst_ip=args["dst_ip"],
        action=args["action"],
        protocol=args["protocol"],
        protocol_upper=args["protocol"].upper(),
        dst_port=args["dst_port"],
        comment=args["comment"],
        log_line=log_line
    )
    return rule.strip()

# ------------------------
# SALVAR ARQUIVOS
# ------------------------
def save_files(rule, args):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = Path(f"firewall_rule_{timestamp}.txt")
    txt_file.write_text(rule)
    console.print(f"[bold green]TXT salvo:[/bold green] {txt_file}")

    if args["json"]:
        json_file = Path(f"firewall_rule_{timestamp}.json")
        json_file.write_text(json.dumps(args | {"rule": rule}, indent=4))
        console.print(f"[bold green]JSON salvo:[/bold green] {json_file}")

    if args["yaml"]:
        yaml_file = Path(f"firewall_rule_{timestamp}.yaml")
        yaml_file.write_text(yaml.dump(args | {"rule": rule}, sort_keys=False))
        console.print(f"[bold green]YAML salvo:[/bold green] {yaml_file}")

# ------------------------
# MAIN
# ------------------------
def main():
    init_db()

    # Se passar parâmetros CLI, usar argparse
    parser = argparse.ArgumentParser(description="Gerador de Regras Firewall")
    parser.add_argument("-f", "--firewall", choices=FIREWALL_TEMPLATES.keys())
    parser.add_argument("-n", "--name")
    parser.add_argument("-a", "--action", choices=["permit","deny"])
    parser.add_argument("-p", "--protocol", choices=["tcp","udp","icmp","all"])
    parser.add_argument("-so", "--src_ip")
    parser.add_argument("-si", "--src_interface")
    parser.add_argument("-do", "--dst_ip")
    parser.add_argument("-di", "--dst_interface")
    parser.add_argument("-sp", "--src_port")
    parser.add_argument("-dp", "--dst_port")
    parser.add_argument("-l", "--log", action="store_true")
    parser.add_argument("-c", "--comment")
    parser.add_argument("--dry_run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--yaml", action="store_true")
    parser.add_argument("--history", action="store_true")
    args_cli = parser.parse_args()

    if args_cli.history:
        show_history()
        sys.exit(0)

    if any(vars(args_cli).values()):
        # Modo CLI
        args = vars(args_cli)
    else:
        # Modo interativo
        args = get_input_interactive()

    rule = generate_rule(args)
    console.print("\n[bold yellow]=== Regra Gerada ===[/bold yellow]\n")
    console.print(rule)

    if not args.get("dry_run", False):
        save_files(rule, args)
        save_history(args["firewall"], args["name"], rule)
    else:
        console.print("[italic cyan]Dry-run: regra não salva nem adicionada ao histórico[/italic cyan]")

if __name__ == "__main__":
    main()

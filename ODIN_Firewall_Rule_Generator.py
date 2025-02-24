import os
import datetime
import argparse
import sys

def get_user_input():
    """Captura as entradas do usuário via CLI."""
    parser = argparse.ArgumentParser(description="Gerador Automático de Regras de Firewall - ODIN")
    parser.add_argument("-f", "--firewall", required=True, choices=["fortinet", "cisco", "juniper", "mikrotik"], help="Selecione o firewall de destino.")
    parser.add_argument("-n", "--name", required=True, help="Nome da regra.")
    parser.add_argument("-a", "--action", required=True, choices=["permit", "deny"], help="Ação da regra (permitir/bloquear).")
    parser.add_argument("-p", "--protocol", required=True, choices=["tcp", "udp", "icmp", "all"], help="Protocolo da regra.")
    parser.add_argument("-so", "--src_ip", required=True, help="Endereço IP/Sub-rede de origem.")
    parser.add_argument("-si", "--src_interface", required=True, help="Interface de entrada (WAN, LAN, DMZ, etc.).")
    parser.add_argument("-do", "--dst_ip", required=True, help="Endereço IP/Sub-rede de destino.")
    parser.add_argument("-di", "--dst_interface", required=True, help="Interface de saída (WAN, LAN, DMZ, etc.).")
    parser.add_argument("-sp", "--src_port", required=True, help="Porta de origem.")
    parser.add_argument("-dp", "--dst_port", required=True, help="Porta de destino.")
    parser.add_argument("-l", "--log", required=False, action='store_true', help="Ativar log de eventos.")
    parser.add_argument("-c", "--comment", required=False, help="Descrição da regra.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    return parser.parse_args()

def generate_firewall_rule(args):
    """Gera a regra baseada nos parâmetros fornecidos."""
    try:
        rule = ""
        if args.firewall == "fortinet":
            rule = f"""
            config firewall policy
                edit 10
                set name \"{args.name}\"
                set srcintf \"{args.src_interface}\"
                set dstintf \"{args.dst_interface}\"
                set srcaddr \"{args.src_ip}\"
                set dstaddr \"{args.dst_ip}\"
                set action {args.action}
                set service \"{args.protocol.upper()}\"
                {'set logtraffic enable' if args.log else ''}
                set comments \"{args.comment}\"
                next
            end
            """
        elif args.firewall == "cisco":
            rule = f"access-list OUTSIDE_IN extended {args.action} {args.protocol} {args.src_ip} host {args.dst_ip} eq {args.dst_port}"
        elif args.firewall == "juniper":
            rule = f"""
            set security policies from-zone {args.src_interface} to-zone {args.dst_interface} policy {args.name} match source-address {args.src_ip}
            set security policies from-zone {args.src_interface} to-zone {args.dst_interface} policy {args.name} match destination-address {args.dst_ip}
            set security policies from-zone {args.src_interface} to-zone {args.dst_interface} policy {args.name} match application {args.protocol}
            set security policies from-zone {args.src_interface} to-zone {args.dst_interface} policy {args.name} then {args.action}
            {'set security policies from-zone {args.src_interface} to-zone {args.dst_interface} policy {args.name} then log session-init' if args.log else ''}
            """
        elif args.firewall == "mikrotik":
            rule = f"/ip firewall filter add chain=forward action={args.action} src-address={args.src_ip} dst-address={args.dst_ip} protocol={args.protocol} dst-port={args.dst_port} comment=\"{args.comment}\""
        
        return rule.strip()
    except Exception as e:
        print(f"Erro ao gerar a regra: {e}")
        sys.exit(1)

def save_to_file(rule, args):
    """Salva as regras geradas em um arquivo .txt."""
    try:
        filename = f"firewall_rules_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as file:
            file.write(rule)
        print(f"\nRegras salvas em: {filename}\n")
    except Exception as e:
        print(f"Erro ao salvar o arquivo: {e}")
        sys.exit(1)

def main():
    """Função principal que orquestra a execução."""
    try:
        args = get_user_input()
        rule = generate_firewall_rule(args)
        print("\n=== Regra Gerada ===")
        print(rule)
        save_to_file(rule, args)
    except Exception as e:
        print(f"Erro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

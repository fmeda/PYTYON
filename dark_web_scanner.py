import argparse
from getpass import getpass
import sys

def parse_arguments():
    class MyArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            print(f"\n[ERRO] {message}\n")
            self.print_help()
            sys.exit(1)

    parser = MyArgumentParser(
        description="""
Dark Web Scanner Enterprise 2025+

Ferramenta de monitoramento de vazamentos na Dark Web com recursos corporativos:

- Monitoramento contínuo de múltiplas palavras-chave
- Ranking de risco (Alta/Média/Baixa)
- Exportação JSON, CSV, PDF
- Dashboard web interativo
- Alertas via Slack/Teams

EXEMPLOS DE USO:
  python dark_web_scanner.py -k email@example.com senha123 -j
  python dark_web_scanner.py -k cpf123 -c -p -a SUA_API_KEY
  python dark_web_scanner.py -k usuario1 usuario2 -d -i 3600
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-k", "--keywords",
        type=str,
        nargs='+',
        required=True,
        help="Palavras-chave para busca na Dark Web (ex.: emails, senhas, CPF)."
    )
    parser.add_argument("-j", "--json", action="store_true", help="Exportar resultados em JSON.")
    parser.add_argument("-c", "--csv", action="store_true", help="Exportar resultados em CSV.")
    parser.add_argument("-p", "--pdf", action="store_true", help="Exportar resultados em PDF.")
    parser.add_argument("-a", "--apikey", type=str, help="API Key (será solicitada se não fornecida).")
    parser.add_argument("-d", "--dashboard", action="store_true", help="Iniciar dashboard web interativo.")
    parser.add_argument("-i", "--interval", type=int, default=0, help="Intervalo em segundos para monitoramento contínuo (0 = apenas uma execução).")

    args = parser.parse_args()

    # Solicita API Key se não fornecida
    if not args.apikey:
        try:
            args.apikey = getpass("Digite sua API Key: ")
        except KeyboardInterrupt:
            print("\n[INFO] Execução interrompida pelo usuário (Ctrl+C). Saindo...")
            sys.exit(0)

    return args

# ==========================
# Exemplo de uso principal
# ==========================
if __name__ == "__main__":
    try:
        args = parse_arguments()
        print(f"Palavras-chave: {args.keywords}")
        print(f"JSON: {args.json}, CSV: {args.csv}, PDF: {args.pdf}")
        print(f"Dashboard: {args.dashboard}, Intervalo: {args.interval} segundos")
    except KeyboardInterrupt:
        print("\n[INFO] Execução interrompida pelo usuário (Ctrl+C). Saindo...")
        sys.exit(0)

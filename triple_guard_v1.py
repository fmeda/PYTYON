import argparse
import sys
import time

def build_argparser():
    parser = argparse.ArgumentParser(
        prog="triple_guard.py",
        description=(
            "Triple Guard 2025 - Criptografia tripla, proteção de credenciais e armadilhas anti-brute-force.\n"
            "Use um dos subcomandos: encrypt, decrypt, shred, protection.\n"
        ),
        epilog=(
            "Exemplos:\n"
            "  python triple_guard.py encrypt -i dados.txt -o dados.tg -k dados.key\n"
            "  python triple_guard.py decrypt -i dados.tg -k dados.key -o dados_restaurados --trap --max-fail 3\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    # FLAGS GLOBAIS
    parser.add_argument(
        "--no-auto-install",
        action="store_true",
        help="Desativa a instalação automática de dependências Python."
    )
    parser.add_argument(
        "--requirements",
        metavar="ARQ",
        help="Instala dependências a partir de um arquivo requirements.txt com hashes."
    )

    # SUBPARSERS
    sub = parser.add_subparsers(dest="cmd", help="Comando a executar (encrypt, decrypt, shred, protection)")

    # ----- ENCRYPT -----
    pe = sub.add_parser(
        "encrypt",
        help="Criptografar arquivo ou diretório."
    )
    pe.add_argument("-i","--input", required=True, help="Arquivo ou pasta de entrada a ser criptografada.")
    pe.add_argument("-o","--output", required=True, help="Arquivo de saída .tg criptografado.")
    pe.add_argument("-k","--keyfile", required=True, help="Arquivo keyfile .key que será criado.")
    pe.add_argument("--passphrase", help="Passphrase do KEK (não recomendado passar em CLI).")
    pe.add_argument("--opsec", action="store_true", help="Minimiza metadados como timestamp e nome do arquivo original.")
    pe.set_defaults(func=lambda args: print("Encrypt chamado com:", args))

    # ----- DECRYPT -----
    pd = sub.add_parser(
        "decrypt",
        help="Descriptografar arquivo ou diretório."
    )
    pd.add_argument("-i","--input", required=True, help="Arquivo .tg a ser descriptografado.")
    pd.add_argument("-k","--keyfile", required=True, help="Arquivo .key correspondente ao .tg.")
    pd.add_argument("-o","--output", required=True, help="Diretório ou arquivo de saída restaurado.")
    pd.add_argument("--passphrase", help="Passphrase do KEK (não recomendado passar em CLI).")
    pd.add_argument("--trap", action="store_true", help="Ativa armadilha: destrói keyfile após N falhas consecutivas.")
    pd.add_argument("--max-fail", type=int, default=3, help="Número máximo de tentativas antes de disparar armadilha.")
    pd.set_defaults(func=lambda args: print("Decrypt chamado com:", args))

    # ----- SHRED -----
    ps = sub.add_parser(
        "shred",
        help="Apagar e sobrescrever arquivo ou diretório."
    )
    ps.add_argument("-p","--path", required=True, help="Arquivo ou pasta a ser destruído.")
    ps.add_argument("--passes", type=int, default=3, help="Número de sobrescritas (quanto maior, mais seguro).")
    ps.set_defaults(func=lambda args: print("Shred chamado com:", args))

    # ----- PROTECTION -----
    prot = sub.add_parser(
        "protection",
        help="Gerenciar proteção/integridade do script (.tg_prot)."
    )
    prot.add_argument("--init", action="store_true", help="Inicializa ou atualiza proteção (.tg_prot).")
    prot.add_argument("--verify", action="store_true", help="Verifica integridade do script usando .tg_prot.")
    prot.add_argument("--force", action="store_true", help="Força recriação de .tg_prot mesmo que já exista.")
    prot.add_argument("--passphrase", help="Passphrase mestre para init ou verify.")
    prot.set_defaults(func=lambda args: print("Protection chamado com:", args))

    return parser


def main():
    try:
        parser = build_argparser()
        args = parser.parse_args()

        if not args.cmd:
            parser.print_help()
            sys.exit(1)

        args.func(args)

    except KeyboardInterrupt:
        print("\nExecução interrompida pelo usuário (Ctrl+C). Saindo...")
        sys.exit(0)
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

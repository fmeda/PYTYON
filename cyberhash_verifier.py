#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script: CyberHash Verifier
Função: Validar o hash de um arquivo comparando com valor fornecido pela fonte e gerar parecer técnico.
Autor: Analista Cyber
"""

import importlib
import subprocess
import sys
import os
import hashlib
import logging
from datetime import datetime
from argparse import ArgumentParser, RawTextHelpFormatter


# ==========================
# Pré-check de módulos
# ==========================
def pre_check_modulos(modulos: list) -> None:
    """Verifica se os módulos necessários estão instalados e tenta instalar se faltarem."""
    for modulo in modulos:
        try:
            importlib.import_module(modulo)
        except ImportError:
            logging.warning(f"[AVISO] Módulo '{modulo}' não encontrado. Instalando...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", modulo])


MODULOS_NECESSARIOS = []  # Lista para futuras dependências externas
pre_check_modulos(MODULOS_NECESSARIOS)


# ==========================
# Configuração de logging
# ==========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


# ==========================
# Função para cálculo de hash
# ==========================
def calcular_hash(caminho_arquivo: str, algoritmo: str) -> str:
    """Calcula o hash do arquivo usando o algoritmo especificado."""
    try:
        h = hashlib.new(algoritmo)
    except ValueError:
        logging.error(f"Algoritmo de hash inválido: {algoritmo}")
        sys.exit(1)

    try:
        with open(caminho_arquivo, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                h.update(bloco)
        return h.hexdigest()
    except FileNotFoundError:
        logging.error(f"Arquivo não encontrado: {caminho_arquivo}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permissão negada ao acessar o arquivo: {caminho_arquivo}")
        sys.exit(1)


# ==========================
# Função para gerar parecer
# ==========================
def gerar_parecer(arquivo: str, hash_fonte: str, hash_calculado: str, algoritmo: str) -> None:
    """Gera parecer técnico sobre a integridade do arquivo."""
    resultado = "APROVADO" if hash_calculado.lower() == hash_fonte.lower() else "REPROVADO"

    parecer = f"""
===============================================
PARECER TÉCNICO DE INTEGRIDADE DE ARQUIVO
===============================================
Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Arquivo Avaliado: {arquivo}
Algoritmo Utilizado: {algoritmo.upper()}

HASH de Referência (Fonte): {hash_fonte}
HASH Calculado (Arquivo):   {hash_calculado}

Status de Integridade: {resultado}

Análise:
- {'O arquivo está íntegro, sem evidências de alteração.' if resultado == 'APROVADO' else 'O arquivo apresenta divergência de hash, podendo indicar corrupção, alteração não autorizada ou erro de transferência.'}

Recomendação:
- {'Nenhuma ação corretiva necessária.' if resultado == 'APROVADO' else 'Baixar novamente o arquivo da fonte confiável, validar integridade e, se persistir, investigar possível comprometimento.'}

Responsável pela Validação:
Analista de Cibersegurança - Sistema Automático

===============================================
"""

    print(parecer)

    nome_relatorio = f"parecer_integridade_{os.path.basename(arquivo)}.txt"
    try:
        with open(nome_relatorio, "w", encoding="utf-8") as rel:
            rel.write(parecer)
        logging.info(f"Parecer salvo em: {nome_relatorio}")
    except PermissionError:
        logging.error("Permissão negada ao salvar o relatório.")


# ==========================
# Função principal
# ==========================
def main() -> None:
    parser = ArgumentParser(
        prog="cyberhash_verifier.py",
        description="Valida a integridade de um arquivo comparando seu hash com o hash de referência.",
        epilog=(
            "Exemplo de uso:\n"
            "  python3 cyberhash_verifier.py -f arquivo.zip -a sha256 -r 5e884898...\n"
            "  python3 cyberhash_verifier.py --file /tmp/teste.iso --referencia abc123 --algoritmo sha512\n\n"
            "Observações:\n"
            "  - Utilize sempre o hash fornecido pela fonte oficial.\n"
            "  - Prefira SHA256 ou SHA512, pois MD5/SHA1 têm vulnerabilidades conhecidas."
        ),
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", help="Caminho do arquivo a ser verificado.")
    parser.add_argument("-a", "--algoritmo", choices=["md5", "sha1", "sha256", "sha512"], default="sha256", help="Algoritmo de hash a ser utilizado.")
    parser.add_argument("-r", "--referencia", help="Hash de referência fornecido pela fonte.")

    # Caso nenhum argumento seja passado, mostra exemplo
    if len(sys.argv) == 1:
        print("\n[ERRO] Argumentos obrigatórios não fornecidos.\n")
        print("Exemplo de uso:")
        print("    python3 cyberhash_verifier.py -f arquivo.zip -a sha256 -r 5e884898...\n")
        print("Para mais detalhes, use:")
        print("    python3 cyberhash_verifier.py --help\n")
        sys.exit(1)

    args = parser.parse_args()

    # Validação de obrigatórios
    if not args.file or not args.referencia:
        print("\n[ERRO] Os parâmetros -f/--file e -r/--referencia são obrigatórios.\n")
        print("Exemplo de uso:")
        print("    python3 cyberhash_verifier.py -f arquivo.zip -a sha256 -r 5e884898...\n")
        print("Para mais detalhes, use:")
        print("    python3 cyberhash_verifier.py --help\n")
        sys.exit(1)

    hash_calc = calcular_hash(args.file, args.algoritmo)
    gerar_parecer(args.file, args.referencia, hash_calc, args.algoritmo)


if __name__ == "__main__":
    main()

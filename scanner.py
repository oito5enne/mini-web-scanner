#!/usr/bin/env python3
"""Mini Web Scanner — análise passiva de postura de segurança.

USO ÉTICO: rode apenas contra sistemas que você possui ou para os quais
tem autorização por escrito, ou contra alvos de treino propositais
(OWASP Juice Shop, DVWA, testphp.vulnweb.com). O scanner é passivo —
só faz requisições HTTP padrão e lê as respostas — mas escanear
terceiros sem permissão pode ser ilegal.
"""
import argparse
import sys

from scanner import checks
from scanner.report import to_console, to_json
from scanner.utils import normalize_url


def run_scan(target):
    findings = []
    resp, reach = checks.check_reachability(target)
    findings += reach
    if resp is None:
        return findings  # inacessível: não há o que mais checar

    for check in checks.ALL_CHECKS_REQUIRING_RESP:
        findings += check(resp)
    for check in checks.ALL_CHECKS_REQUIRING_URL:
        findings += check(target)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="URL ou domínio do alvo")
    parser.add_argument("--json", metavar="ARQUIVO",
                        help="Salva o relatório em JSON no caminho indicado")
    parser.add_argument("--no-color", action="store_true",
                        help="Desliga cores no console")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Confirma que você tem permissão para escanear o alvo")
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        print("Recusado: confirme a autorização com --i-have-authorization.\n"
              "Escaneie apenas sistemas próprios, autorizados ou de treino.",
              file=sys.stderr)
        return 2

    try:
        target = normalize_url(args.target)
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    findings = run_scan(target)
    print(to_console(target, findings, use_color=not args.no_color))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(target, findings))
        print(f"\nRelatório JSON salvo em: {args.json}")

    # Código de saída diferente de zero se houver achado HIGH (útil em CI)
    return 1 if any(f["severity"] == "HIGH" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())

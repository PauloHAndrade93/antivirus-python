"""
AV-Py - CLI principal do antivirus defensivo.

Uso:
    python av.py scan <pasta> [--quarantine]
    python av.py netmon [--beacon]
    python av.py quarantine --list
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from core import hash_scanner, network_monitor, quarantine, yara_scanner

PASTA_REGRAS = Path(__file__).parent / "rules"
LISTA_HASH_LOCAL = PASTA_REGRAS / "hashes_locais.txt"


# ---------- utilidades de impressao ---------- #

def info(msg: str) -> None:
    print(f"[i] {msg}")


def alerta(msg: str) -> None:
    print(f"[!] {msg}")


def ok(msg: str) -> None:
    print(f"[+] {msg}")


# ---------- comandos ---------- #

def cmd_scan(args: argparse.Namespace) -> int:
    raiz = Path(args.pasta).resolve()
    if not raiz.exists():
        alerta(f"Pasta nao encontrada: {raiz}")
        return 2

    info(f"Alvo: {raiz}")

    # Hash scan
    lista_local = hash_scanner.carregar_lista_local(LISTA_HASH_LOCAL)
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if api_key:
        info("Hash scanner: online (MalwareBazaar)")
    else:
        info(f"Hash scanner: offline (lista local com {len(lista_local)} hashes)")

    deteccoes_hash = hash_scanner.escanear(raiz, lista_local, api_key=api_key)
    for d in deteccoes_hash:
        alerta(f"HASH match: {d.arquivo}")
        print(f"     sha256: {d.sha256}")
        print(f"     fonte:  {d.fonte} / {d.detalhe}")

    # YARA scan
    try:
        ruleset = yara_scanner.compilar_regras(PASTA_REGRAS)
        matches = yara_scanner.escanear(raiz, ruleset)
        info(f"YARA: {len(matches)} match(es)")
        for m in matches:
            alerta(f"YARA match: {m.arquivo}")
            print(f"     regra:  {m.regra}  tags={m.tags}")
            if m.strings_casadas:
                print(f"     casou:  {', '.join(m.strings_casadas)}")
    except RuntimeError as e:
        alerta(f"YARA pulado: {e}")
        matches = []

    # Quarentena
    if args.quarantine:
        alvos = {d.arquivo: ("hash", d.sha256, d.detalhe) for d in deteccoes_hash}
        for m in matches:
            alvos.setdefault(m.arquivo, ("yara", None, f"{m.regra} {m.tags}"))

        for arquivo, (origem, sha, detalhe) in alvos.items():
            try:
                destino = quarantine.isolar(arquivo, motivo=f"{origem}:{detalhe}", sha256=sha)
                ok(f"Isolado: {arquivo}  ->  {destino}")
            except OSError as e:
                alerta(f"Nao consegui isolar {arquivo}: {e}")

    if not deteccoes_hash and not matches:
        ok("Nenhuma ameaca encontrada.")
        return 0
    return 1


def cmd_netmon(args: argparse.Namespace) -> int:
    if args.beacon:
        info(f"Observando beaconing por {args.janela}s...")
        alertas = network_monitor.detectar_beaconing(janela_segundos=args.janela)
    else:
        info("Snapshot das conexoes de saida...")
        alertas = network_monitor.varrer_conexoes_ativas()

    if not alertas:
        ok("Nenhuma conexao suspeita.")
        return 0

    for a in alertas:
        alerta(f"[{a.processo} pid={a.pid}] {a.ip_remoto}:{a.porta_remota}")
        print(f"     motivo: {a.motivo}")
    return 1


def cmd_quarantine(args: argparse.Namespace) -> int:
    if args.list:
        entradas = quarantine.listar()
        if not entradas:
            info("Quarentena vazia.")
            return 0
        for e in entradas:
            print(f"- {e['momento']}  {e['origem']}")
            print(f"    motivo: {e['motivo']}")
            print(f"    hoje em: {e['quarentena']}")
        return 0
    alerta("Use --list para listar a quarentena.")
    return 2


# ---------- parser ---------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="av",
        description="AV-Py - antivirus defensivo em Python (MVP).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Escaneia uma pasta (hash + YARA).")
    s.add_argument("pasta", help="Pasta a escanear.")
    s.add_argument("--quarantine", action="store_true",
                   help="Move arquivos detectados para quarentena.")
    s.set_defaults(func=cmd_scan)

    n = sub.add_parser("netmon", help="Monitor de rede defensivo.")
    n.add_argument("--beacon", action="store_true",
                   help="Modo beaconing (amostragem na janela).")
    n.add_argument("--janela", type=int, default=90,
                   help="Janela em segundos (modo beacon). Padrao 90.")
    n.set_defaults(func=cmd_netmon)

    q = sub.add_parser("quarantine", help="Gerencia quarentena.")
    q.add_argument("--list", action="store_true", help="Lista arquivos em quarentena.")
    q.set_defaults(func=cmd_quarantine)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

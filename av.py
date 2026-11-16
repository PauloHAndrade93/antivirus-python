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

from core import (
    hash_scanner, network_monitor, persistence_checker,
    quarantine, ransom_watcher, yara_scanner,
)

PASTA_REGRAS = Path(__file__).parent / "rules"
LISTA_HASH_LOCAL = PASTA_REGRAS / "hashes_locais.txt"
LOG_RANSOM = Path(__file__).parent / "logs" / "ransom.log"


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


def cmd_watch(args: argparse.Namespace) -> int:
    pastas = [Path(p) for p in args.pastas]
    try:
        alertas = ransom_watcher.observar(
            pastas=pastas,
            log_alertas=LOG_RANSOM,
            janela_segundos=args.janela,
            limite_eventos=args.limite,
            duracao_segundos=args.duracao,
        )
    except RuntimeError as e:
        alerta(str(e))
        return 2
    if alertas:
        alerta(f"Total de alertas gerados: {len(alertas)}  (log: {LOG_RANSOM})")
        return 1
    ok("Nenhum comportamento de ransomware observado.")
    return 0


def cmd_persist(args: argparse.Namespace) -> int:
    resultado = persistence_checker.verificar_tudo()

    rotulos = {
        "registry": "Chaves Run do Registro (T1547.001)",
        "startup": "Pastas Startup (T1547.001)",
        "tarefa":  "Tarefas agendadas (T1053.005)",
        "servico": "Servicos com inicio automatico (T1543.003)",
    }

    total = 0
    suspeitos = 0
    for chave, itens in resultado.items():
        mostrar = itens if args.all else [i for i in itens if i.suspeito]
        if not mostrar and not args.all:
            continue
        info(f"=== {rotulos[chave]} ===")
        if not mostrar:
            print("    (vazio)")
        for it in mostrar:
            total += 1
            prefixo = "[!]" if it.suspeito else "[ ]"
            if it.suspeito:
                suspeitos += 1
            print(f"  {prefixo} {it.nome}")
            print(f"       local:   {it.localizacao}")
            print(f"       comando: {it.comando}")
            for s in it.sinais:
                print(f"       sinal:   {s}")

    print()
    if suspeitos:
        alerta(f"{suspeitos} item(ns) suspeito(s) de {total} exibido(s).")
        return 1
    ok(f"Nenhuma persistencia suspeita detectada (varreu {sum(len(v) for v in resultado.values())} entrada(s) no total).")
    return 0


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

    pr = sub.add_parser("persist", help="Audita pontos de persistencia do Windows.")
    pr.add_argument("--all", action="store_true",
                    help="Lista tudo, nao so os suspeitos.")
    pr.set_defaults(func=cmd_persist)

    w = sub.add_parser("watch", help="Observa pastas contra ransomware (heuristico).")
    w.add_argument("pastas", nargs="+", help="Pasta(s) a observar recursivamente.")
    w.add_argument("--janela", type=int, default=10,
                   help="Janela deslizante em segundos (padrao 10).")
    w.add_argument("--limite", type=int, default=30,
                   help="Eventos na janela para disparar alerta de massa (padrao 30).")
    w.add_argument("--duracao", type=int, default=None,
                   help="Duracao total em segundos. Omitir = roda ate Ctrl+C.")
    w.set_defaults(func=cmd_watch)

    q = sub.add_parser("quarantine", help="Gerencia quarentena.")
    q.add_argument("--list", action="store_true", help="Lista arquivos em quarentena.")
    q.set_defaults(func=cmd_quarantine)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

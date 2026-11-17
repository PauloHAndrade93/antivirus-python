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
    full_scan, hash_scanner, hosts_integrity, network_monitor,
    persistence_checker, process_scanner, quarantine, ransom_watcher,
    threat_feeds, virustotal, yara_scanner,
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

    # VT lookup opcional: pega os hashes dos arquivos escaneados que nao
    # casaram com a lista local, e pergunta ao VirusTotal se ele conhece.
    # Respeita rate limit (4/min). So vale se o usuario pediu --vt e tiver chave.
    deteccoes_vt: list[hash_scanner.Deteccao] = []
    vt_key = os.environ.get("VT_API_KEY", "")
    if args.vt:
        if not vt_key:
            alerta("--vt pedido mas VT_API_KEY nao esta no ambiente. Pulando VT.")
        else:
            info("VirusTotal: verificando hashes nao-casados (pode demorar pelo rate limit)...")
            hashes_ja_detectados = {d.sha256 for d in deteccoes_hash}
            analisados: set[str] = set()
            for arquivo in hash_scanner.iter_arquivos(raiz):
                try:
                    if arquivo.stat().st_size > 32 * 1024 * 1024:  # VT free: 32MB
                        continue
                    digest = hash_scanner.sha256_do_arquivo(arquivo)
                except (OSError, PermissionError):
                    continue
                if digest in hashes_ja_detectados or digest in analisados:
                    continue
                analisados.add(digest)
                v = virustotal.consultar_hash(digest, vt_key)
                if v.nivel in ("malicioso", "suspeito"):
                    alerta(f"VT match: {arquivo}")
                    print(f"     {v.resumo()}")
                    deteccoes_vt.append(
                        hash_scanner.Deteccao(
                            arquivo=arquivo, sha256=digest,
                            fonte="virustotal", detalhe=v.resumo(),
                        )
                    )

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
        for d in deteccoes_vt:
            alvos.setdefault(d.arquivo, ("virustotal", d.sha256, d.detalhe))
        for m in matches:
            alvos.setdefault(m.arquivo, ("yara", None, f"{m.regra} {m.tags}"))

        for arquivo, (origem, sha, detalhe) in alvos.items():
            try:
                destino = quarantine.isolar(arquivo, motivo=f"{origem}:{detalhe}", sha256=sha)
                ok(f"Isolado: {arquivo}  ->  {destino}")
            except OSError as e:
                alerta(f"Nao consegui isolar {arquivo}: {e}")

    if not deteccoes_hash and not matches and not deteccoes_vt:
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


def cmd_fullscan(args: argparse.Namespace) -> int:
    drives = full_scan.listar_drives()

    letras = None
    if args.drive:
        # Aceita: "C", "C:", "C:\\", "c", "c:\\" -> sempre normaliza para "C:"
        letras = set()
        for d in args.drive:
            s = d.strip().rstrip("\\").rstrip(":").upper()
            if s:
                letras.add(s + ":")
    drives = full_scan.filtrar_drives(
        drives, apenas_usb=args.usb_only, somente_letras=letras,
    )
    if not drives:
        alerta("Nenhum drive selecionado para escanear.")
        return 2

    info("Drives selecionados:")
    for d in drives:
        print(f"  - {d.letra}  tipo={d.tipo}  fs={d.fstype}")

    # Prepara motores
    lista_local = hash_scanner.carregar_lista_local(LISTA_HASH_LOCAL)
    api_key_mb = os.environ.get("MALWAREBAZAAR_API_KEY") if args.use_mb else None
    try:
        ruleset = yara_scanner.compilar_regras(PASTA_REGRAS)
    except RuntimeError as e:
        alerta(f"YARA pulado: {e}")
        ruleset = None

    progresso = full_scan.Progresso(inicio=__import__("time").time())
    todas: list[full_scan.DeteccaoCompleta] = []

    def _mostra(prog: full_scan.Progresso) -> None:
        print(f"  {prog.resumo()}")

    try:
        for d in drives:
            info(f"Varrendo {d.letra} ({d.tipo})...")
            deteccoes, progresso = full_scan.escanear_drive(
                drive=d,
                lista_hash_local=lista_local,
                api_key_mb=api_key_mb,
                ruleset_yara=ruleset,
                tamanho_max_mb=args.max_mb,
                intervalo_progresso=args.progresso,
                on_progresso=_mostra,
                progresso=progresso,
            )
            todas.extend(deteccoes)
    except KeyboardInterrupt:
        alerta("Interrompido pelo usuario (Ctrl+C).")

    # Relatorio final
    rel = Path(__file__).parent / "logs" / f"fullscan_{__import__('time').strftime('%Y%m%d-%H%M%S')}.log"
    rel.parent.mkdir(parents=True, exist_ok=True)
    with open(rel, "w", encoding="utf-8") as f:
        f.write(progresso.resumo("final") + "\n\n")
        for det in todas:
            linha = f"[{det.motor}] {det.arquivo}  -  {det.detalhe}"
            if det.sha256:
                linha += f"  sha256={det.sha256}"
            f.write(linha + "\n")
    ok(f"Relatorio: {rel}")

    print("\n" + progresso.resumo("final"))
    if todas:
        alerta(f"{len(todas)} deteccao(oes). Veja o relatorio acima.")
        for det in todas[:50]:  # limita o print; o log tem tudo
            print(f"  [{det.motor}] {det.arquivo}")
            print(f"       {det.detalhe}")
        if args.quarantine:
            isolados = 0
            for det in todas:
                try:
                    quarantine.isolar(det.arquivo, motivo=f"{det.motor}:{det.detalhe}", sha256=det.sha256)
                    isolados += 1
                except OSError as e:
                    alerta(f"Nao consegui isolar {det.arquivo}: {e}")
            ok(f"{isolados} arquivo(s) isolado(s) em quarantine/.")
        return 1

    ok("Nenhuma ameaca encontrada.")
    return 0


def cmd_procs(args: argparse.Namespace) -> int:
    alertas = process_scanner.auditar()
    if not alertas:
        ok("Nenhum processo suspeito detectado.")
        return 0
    for a in alertas:
        alerta(f"[pid {a.pid}] {a.nome}")
        print(f"       caminho: {a.caminho or '(sem exe)'}")
        print(f"       pai:     {a.pai_nome} (pid {a.pai_pid})")
        for s in a.sinais:
            print(f"       sinal:   {s}")
    alerta(f"{len(alertas)} processo(s) suspeito(s).")
    return 1


def cmd_hosts(args: argparse.Namespace) -> int:
    alertas = hosts_integrity.auditar()
    if not alertas:
        ok(f"Arquivo hosts limpo ({hosts_integrity.HOSTS_PATH}).")
        return 0
    for a in alertas:
        if a.tipo == "erro":
            alerta(f"erro: {a.detalhe}")
            continue
        alerta(f"[linha {a.numero_linha}] {a.linha}")
        print(f"       tipo:    {a.tipo}")
        print(f"       detalhe: {a.detalhe}")
    return 1


def cmd_feeds_update(args: argparse.Namespace) -> int:
    if not threat_feeds.obter_api_key():
        alerta("Chave abuse.ch nao configurada.")
        alerta("Cadastre gratuitamente em https://auth.abuse.ch/ e exporte:")
        alerta('  setx ABUSE_CH_API_KEY "sua_chave"    (depois abra um CMD novo)')
        return 2
    pasta_regras = PASTA_REGRAS
    falhas: list[str] = []

    if not args.urlhaus_only:
        try:
            adic, total = threat_feeds.atualizar_malwarebazaar(pasta_regras / "hashes_locais.txt")
            ok(f"MalwareBazaar: +{adic} / total {total}")
        except Exception as e:
            alerta(f"MalwareBazaar falhou: {e}")
            falhas.append("MalwareBazaar")

    if not args.mb_only:
        try:
            adic, total = threat_feeds.atualizar_urlhaus(pasta_regras / "urls_maliciosas.txt")
            ok(f"ThreatFox (URLs): +{adic} / total {total}")
        except Exception as e:
            alerta(f"ThreatFox falhou: {e}")
            falhas.append("ThreatFox")

    return 1 if falhas else 0


def cmd_vt(args: argparse.Namespace) -> int:
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        alerta("Variavel VT_API_KEY nao configurada. Cadastre uma chave gratuita em")
        alerta("https://www.virustotal.com/gui/my-apikey e exporte VT_API_KEY.")
        return 2
    for alvo in args.alvos:
        v = virustotal.consultar_auto(alvo, api_key)
        if v.nivel in ("malicioso", "suspeito"):
            alerta(v.resumo())
        elif v.nivel == "erro":
            alerta(v.resumo())
        else:
            info(v.resumo())
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
    s.add_argument("--vt", action="store_true",
                   help="Tambem consulta hashes nao-casados no VirusTotal (requer VT_API_KEY).")
    s.set_defaults(func=cmd_scan)

    n = sub.add_parser("netmon", help="Monitor de rede defensivo.")
    n.add_argument("--beacon", action="store_true",
                   help="Modo beaconing (amostragem na janela).")
    n.add_argument("--janela", type=int, default=90,
                   help="Janela em segundos (modo beacon). Padrao 90.")
    n.set_defaults(func=cmd_netmon)

    fs = sub.add_parser("fullscan", help="Escaneia drives inteiros (HD, SSD, pendrive).")
    fs.add_argument("--drive", action="append",
                    help="Limita a esse(s) drive(s), ex.: --drive C: --drive E:. Sem = todos os fixos+removiveis.")
    fs.add_argument("--usb-only", action="store_true",
                    help="So drives removiveis (pendrive, cartao SD, HD externo USB).")
    fs.add_argument("--max-mb", type=int, default=100,
                    help="Tamanho maximo por arquivo em MB (padrao 100).")
    fs.add_argument("--progresso", type=int, default=500,
                    help="Imprime progresso a cada N arquivos (padrao 500).")
    fs.add_argument("--use-mb", action="store_true",
                    help="Tambem consulta MalwareBazaar nos hashes (requer MALWAREBAZAAR_API_KEY).")
    fs.add_argument("--quarantine", action="store_true",
                    help="Isola o que for detectado em quarantine/.")
    fs.set_defaults(func=cmd_fullscan)

    pp = sub.add_parser("procs", help="Audita processos em execucao (LOLBAS, pastas suspeitas).")
    pp.set_defaults(func=cmd_procs)

    hh = sub.add_parser("hosts", help="Verifica integridade do arquivo hosts.")
    hh.set_defaults(func=cmd_hosts)

    fu = sub.add_parser("feeds-update", help="Atualiza feeds gratuitos (MalwareBazaar + URLHaus).")
    fu.add_argument("--mb-only", action="store_true", help="So MalwareBazaar.")
    fu.add_argument("--urlhaus-only", action="store_true", help="So URLHaus.")
    fu.set_defaults(func=cmd_feeds_update)

    vt = sub.add_parser("vt", help="Consulta VirusTotal (hash, IP ou dominio).")
    vt.add_argument("alvos", nargs="+", help="Um ou mais hashes, IPs ou dominios.")
    vt.set_defaults(func=cmd_vt)

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

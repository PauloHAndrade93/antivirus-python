"""
AV-Py - painel web local.

Sobe um servidor Flask SO em 127.0.0.1 e executa os comandos do av.py em
subprocessos, mostrando a saida ao vivo no navegador.

Seguranca (um painel que dispara varreduras merece cuidado):
  - escuta apenas em 127.0.0.1 (nada fica exposto na rede)
  - token aleatorio por execucao exigido em toda chamada POST (anti-CSRF)
  - cabecalho Host conferido (anti DNS rebinding)
  - acoes e parametros validados por lista branca; nada passa por shell
  - cabecalhos CSP / X-Frame-Options / nosniff
  - as chaves de API nunca saem do servidor: o painel so sabe se existem

Uso:
    python web/app.py            (abre o navegador sozinho)
    set AVPY_PORTA=9000          (troca a porta, opcional)
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
os.chdir(RAIZ)  # quarantine.py usa caminhos relativos a raiz do projeto

from core import full_scan, quarantine, virustotal  # noqa: E402

PORTA = int(os.environ.get("AVPY_PORTA", "8765"))
TOKEN = secrets.token_urlsafe(32)
HOSTS_OK = {f"127.0.0.1:{PORTA}", f"localhost:{PORTA}"}
ORIGENS_OK = {f"http://{h}" for h in HOSTS_OK}

PASTA_REGRAS = RAIZ / "rules"
PASTA_LOGS = RAIZ / "logs"

MAX_LINHAS = 20000
MAX_JOBS = 30
RE_DRIVE = re.compile(r"^[A-Za-z]:?\\?$")
RE_LOG = re.compile(r"^[\w.\-]+\.log$")

app = Flask(__name__, template_folder="templates", static_folder="static")

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------- seguranca

@app.before_request
def _proteger():
    if request.host not in HOSTS_OK:
        abort(403)
    if request.method == "POST":
        enviado = request.headers.get("X-AVPY-Token", "")
        if not secrets.compare_digest(enviado, TOKEN):
            abort(403)
        origem = request.headers.get("Origin")
        if origem and origem not in ORIGENS_OK:
            abort(403)


@app.after_request
def _cabecalhos(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- validacao

class ErroParam(ValueError):
    pass


def _bool(p: dict, chave: str) -> bool:
    v = p.get(chave)
    if isinstance(v, str):
        return v.lower() in ("1", "true", "on", "sim")
    return bool(v)


def _pasta(valor: str) -> str:
    v = str(valor).strip().strip('"')
    if not v or v.startswith("-"):
        raise ErroParam("Informe uma pasta valida.")
    if not Path(v).is_dir():
        raise ErroParam(f"Pasta nao encontrada: {v}")
    return v


def _inteiro(valor, minimo: int, maximo: int, nome: str) -> int:
    try:
        n = int(valor)
    except (TypeError, ValueError):
        raise ErroParam(f"{nome} precisa ser um numero.")
    if not minimo <= n <= maximo:
        raise ErroParam(f"{nome} deve ficar entre {minimo} e {maximo}.")
    return n


def montar_argv(acao: str, p: dict) -> list[str]:
    """Traduz uma acao do painel para os argumentos do av.py (lista branca)."""
    if acao == "scan":
        argv = ["scan", _pasta(p.get("pasta", ""))]
        if _bool(p, "quarantine"):
            argv.append("--quarantine")
            if _bool(p, "dry_run"):
                argv.append("--dry-run")
        if _bool(p, "vt"):
            argv.append("--vt")
        return argv

    if acao == "fullscan":
        argv = ["fullscan", "--progresso", "200"]
        if _bool(p, "usb_only"):
            argv.append("--usb-only")
        else:
            drive = str(p.get("drive", "todos")).strip()
            if drive and drive != "todos":
                if not RE_DRIVE.match(drive):
                    raise ErroParam("Letra de drive invalida.")
                argv += ["--drive", drive]
        if _bool(p, "quarantine"):
            argv.append("--quarantine")
            if _bool(p, "dry_run"):
                argv.append("--dry-run")
        return argv

    if acao == "netmon":
        if _bool(p, "beacon"):
            janela = _inteiro(p.get("janela", 90), 10, 600, "Janela")
            return ["netmon", "--beacon", "--janela", str(janela)]
        return ["netmon"]

    if acao == "watch":
        linhas = [x for x in str(p.get("pastas", "")).splitlines() if x.strip()]
        if not linhas:
            casa = Path.home()
            linhas = [str(casa / "Documents"), str(casa / "Desktop")]
        pastas = [_pasta(x) for x in linhas[:6]]
        duracao = _inteiro(p.get("duracao", 300), 30, 86400, "Duracao")
        return ["watch", *pastas, "--duracao", str(duracao)]

    if acao == "persist":
        return ["persist", "--all"] if _bool(p, "all") else ["persist"]

    if acao in ("procs", "hosts"):
        return [acao]

    if acao == "feeds":
        return ["feeds-update"]

    if acao == "vt":
        alvos = str(p.get("alvos", "")).split()
        if not alvos:
            raise ErroParam("Informe ao menos um hash, IP ou dominio.")
        if len(alvos) > 4:
            raise ErroParam("No maximo 4 alvos por vez (limite gratuito do VirusTotal).")
        for a in alvos:
            if virustotal.detectar_tipo(a) is None:
                raise ErroParam(f"'{a}' nao parece hash, IP ou dominio.")
        return ["vt", *alvos]

    raise ErroParam("Acao desconhecida.")


# ---------------------------------------------------------------- execucao

def _executar(job_id: str, argv: list[str]) -> None:
    job = JOBS[job_id]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(RAIZ / "av.py"), *argv],
            cwd=str(RAIZ), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            creationflags=flags,
        )
    except OSError as e:
        job.update(status="erro", codigo=2, fim=time.time())
        job["linhas"].append(f"[!] Nao foi possivel iniciar: {e}")
        return

    job["proc"] = proc
    assert proc.stdout is not None
    for linha in proc.stdout:
        linhas = job["linhas"]
        linhas.append(linha.rstrip("\r\n"))
        if len(linhas) > MAX_LINHAS:
            del linhas[: len(linhas) - MAX_LINHAS]
            job["descartadas"] += 1
    proc.wait()
    job["codigo"] = proc.returncode
    job["fim"] = time.time()
    if job["status"] != "cancelado":
        job["status"] = "concluido"


def _resumo_job(j: dict) -> dict:
    return {
        "id": j["id"], "acao": j["acao"], "rotulo": j["rotulo"],
        "status": j["status"], "codigo": j["codigo"],
        "inicio": j["inicio"], "fim": j["fim"],
    }


# ---------------------------------------------------------------- rotas

@app.get("/")
def index():
    return render_template("index.html", token=TOKEN)


@app.post("/api/jobs")
def criar_job():
    corpo = request.get_json(silent=True) or {}
    acao = str(corpo.get("acao", ""))
    params = corpo.get("params") or {}
    if not isinstance(params, dict):
        return jsonify(erro="Parametros invalidos."), 400
    try:
        argv = montar_argv(acao, params)
    except ErroParam as e:
        return jsonify(erro=str(e)), 400

    with JOBS_LOCK:
        if sum(1 for j in JOBS.values() if j["status"] == "rodando") >= 3:
            return jsonify(erro="Ja existem 3 tarefas rodando. Aguarde ou cancele uma."), 429
        job_id = uuid.uuid4().hex[:12]
        JOBS[job_id] = {
            "id": job_id, "acao": acao,
            "rotulo": str(corpo.get("rotulo") or acao)[:80],
            "argv": argv, "status": "rodando", "codigo": None,
            "inicio": time.time(), "fim": None,
            "linhas": [], "descartadas": 0, "proc": None,
        }
        antigos = sorted(JOBS.values(), key=lambda j: j["inicio"])
        for j in antigos[: max(0, len(JOBS) - MAX_JOBS)]:
            if j["status"] != "rodando":
                JOBS.pop(j["id"], None)

    threading.Thread(target=_executar, args=(job_id, argv), daemon=True).start()
    return jsonify(id=job_id)


@app.get("/api/jobs")
def listar_jobs():
    with JOBS_LOCK:
        itens = sorted(JOBS.values(), key=lambda j: j["inicio"], reverse=True)
        return jsonify([_resumo_job(j) for j in itens])


@app.get("/api/jobs/<job_id>")
def ver_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(erro="Tarefa nao encontrada."), 404
    try:
        desde = max(0, int(request.args.get("desde", 0)))
    except ValueError:
        desde = 0
    linhas = job["linhas"]
    total = len(linhas)
    return jsonify(**_resumo_job(job), total=total, linhas=linhas[min(desde, total):])


@app.post("/api/jobs/<job_id>/cancelar")
def cancelar_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(erro="Tarefa nao encontrada."), 404
    proc = job.get("proc")
    if job["status"] == "rodando" and proc and proc.poll() is None:
        job["status"] = "cancelado"
        job["linhas"].append("[i] Cancelado pelo usuario no painel.")
        proc.terminate()
    return jsonify(ok=True)


def _contar_hashes(caminho: Path) -> int:
    if not caminho.exists():
        return 0
    return sum(
        1 for l in caminho.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(l.strip()) == 64 and not l.startswith("#")
    )


def _contar_linhas_dados(caminho: Path) -> int:
    if not caminho.exists():
        return 0
    return sum(
        1 for l in caminho.read_text(encoding="utf-8", errors="replace").splitlines()
        if l.strip() and not l.lstrip().startswith("#")
    )


def _contar_regras_yara() -> int:
    total = 0
    for p in PASTA_REGRAS.glob("*.yar*"):
        texto = p.read_text(encoding="utf-8", errors="replace")
        total += len(re.findall(r"^\s*rule\s+\w+", texto, flags=re.M))
    return total


def _ultimo_fullscan() -> dict | None:
    logs = sorted(PASTA_LOGS.glob("fullscan_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not logs:
        return None
    p = logs[0]
    linhas = p.read_text(encoding="utf-8", errors="replace").splitlines()
    resumo = linhas[0] if linhas else ""
    m = re.search(r"deteccoes=(\d+)", resumo)
    return {
        "arquivo": p.name, "quando": p.stat().st_mtime, "resumo": resumo,
        "deteccoes": int(m.group(1)) if m else None,
    }


@app.get("/api/status")
def status():
    drives = [
        {"letra": d.letra, "tipo": d.tipo, "fs": d.fstype}
        for d in full_scan.listar_drives()
    ]
    return jsonify(
        hashes=_contar_hashes(PASTA_REGRAS / "hashes_locais.txt"),
        urls=_contar_linhas_dados(PASTA_REGRAS / "urls_maliciosas.txt"),
        regras=_contar_regras_yara(),
        quarentena=len(quarantine.listar()),
        drives=drives,
        home=str(Path.home()),
        chaves={
            "virustotal": bool(os.environ.get("VT_API_KEY")),
            "abusech": bool(os.environ.get("ABUSE_CH_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY")),
        },
        ultimo_fullscan=_ultimo_fullscan(),
    )


@app.get("/api/quarentena")
def ver_quarentena():
    return jsonify(list(reversed(quarantine.listar())))


@app.get("/api/relatorios")
def listar_relatorios():
    if not PASTA_LOGS.exists():
        return jsonify([])
    itens = sorted(PASTA_LOGS.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return jsonify([
        {"nome": p.name, "tamanho": p.stat().st_size, "quando": p.stat().st_mtime}
        for p in itens
    ])


@app.get("/api/relatorios/<nome>")
def ler_relatorio(nome: str):
    if not RE_LOG.match(nome):
        abort(404)
    caminho = (PASTA_LOGS / nome).resolve()
    if caminho.parent != PASTA_LOGS.resolve() or not caminho.exists():
        abort(404)
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        conteudo = f.read(2 * 1024 * 1024)
    return jsonify(nome=nome, conteudo=conteudo)


# ---------------------------------------------------------------- main

def main() -> None:
    url = f"http://127.0.0.1:{PORTA}/"
    print("=" * 60)
    print("  AV-Py - painel local")
    print(f"  Abra: {url}")
    print("  So acessivel deste computador. Ctrl+C encerra.")
    print("=" * 60)
    if not os.environ.get("AVPY_NO_BROWSER"):
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    app.run(host="127.0.0.1", port=PORTA, debug=False, threaded=True)


if __name__ == "__main__":
    main()

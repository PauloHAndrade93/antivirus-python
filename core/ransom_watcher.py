"""
Ransom Watcher - detecao heuristica de ransomware em tempo real.

Ransomware tem uma assinatura comportamental muito caracteristica:
  1) Cifragem em massa num intervalo curto (muitos arquivos mexidos / renomeados).
  2) Novas extensoes exoticas (.locked, .encrypted, .wncry, .ryk, ...).
  3) Notas de resgate (HOW_TO_DECRYPT.txt, README_RECOVERY.html, ...).

Esta heuristica observa um ou mais diretorios sensiveis com o 'watchdog',
mantem janela deslizante de eventos e gera alertas quando qualquer um dos
tres sinais ultrapassa o limiar configurado.

Nao bloqueia o processo ofensor. So detecta e grita. Encerrar o atacante
e assunto de modulos futuros (precisa de privilegio e analise de pai).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore


# ---------- configuracao padrao ---------- #

EXTENSOES_SUSPEITAS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cry",
    ".wncry", ".wncryt", ".wcry", ".wnry",
    ".ryk", ".ryuk",
    ".lockbit",          # '.lock' NAO entra: Cargo.lock, yarn.lock, poetry.lock sao legitimos
    ".conti", ".sodinokibi", ".revil",
    ".darkside", ".dharma", ".phobos",
    ".mamba", ".cerber", ".crysis",
    ".cry666", ".payforkey", ".pay2key",
    ".readme", ".help",
}

PADROES_NOTA_RESGATE = [
    re.compile(r"^how[-_\s]*to[-_\s]*decrypt", re.I),
    re.compile(r"^how[-_\s]*to[-_\s]*recover", re.I),
    re.compile(r"^readme[-_\s]*(for[-_\s]*)?decrypt", re.I),
    re.compile(r"^readme[-_\s]*(for[-_\s]*)?recovery", re.I),
    re.compile(r"^decrypt[-_\s]*(instructions|me|files)", re.I),
    re.compile(r"^your[-_\s]*files[-_\s]*(are|have)", re.I),
    # 'ransom' sozinho marcava ate o proprio ransom_watcher.py: exige cara de nota
    re.compile(r"ransom.*\.(txt|html?|hta|rtf|url)$", re.I),
    re.compile(r"^!!!.*readme", re.I),
]


# ---------- modelo de alerta ---------- #

@dataclass
class AlertaRansom:
    tipo: str              # "massa", "extensao", "nota"
    detalhe: str
    caminho: str
    momento: float = field(default_factory=time.time)

    def dict(self) -> dict:
        return {
            "momento": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.momento)),
            "tipo": self.tipo,
            "detalhe": self.detalhe,
            "caminho": self.caminho,
        }


# ---------- handler watchdog ---------- #

class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(
        self,
        janela_segundos: int,
        limite_eventos: int,
        on_alerta: Callable[[AlertaRansom], None],
    ) -> None:
        self.janela = janela_segundos
        self.limite = limite_eventos
        self.on_alerta = on_alerta
        self.eventos: deque[float] = deque()
        self._lock = threading.Lock()
        self._ja_alertou_massa = 0.0  # debounce para nao spammar

    # ---- heuristicas ---- #

    def _marca_evento(self) -> None:
        agora = time.time()
        with self._lock:
            self.eventos.append(agora)
            corte = agora - self.janela
            while self.eventos and self.eventos[0] < corte:
                self.eventos.popleft()
            if len(self.eventos) >= self.limite and (agora - self._ja_alertou_massa) > 10:
                self._ja_alertou_massa = agora
                self.on_alerta(
                    AlertaRansom(
                        tipo="massa",
                        detalhe=(
                            f"{len(self.eventos)} eventos em {self.janela}s "
                            f"(limite={self.limite})"
                        ),
                        caminho="(varios)",
                    )
                )

    def _checa_extensao(self, caminho: str) -> None:
        ext = Path(caminho).suffix.lower()
        if ext and ext in EXTENSOES_SUSPEITAS:
            self.on_alerta(
                AlertaRansom(
                    tipo="extensao",
                    detalhe=f"Extensao tipica de ransomware: {ext}",
                    caminho=caminho,
                )
            )

    def _checa_nota(self, caminho: str) -> None:
        nome = Path(caminho).name
        for pad in PADROES_NOTA_RESGATE:
            if pad.search(nome):
                self.on_alerta(
                    AlertaRansom(
                        tipo="nota",
                        detalhe=f"Possivel nota de resgate (padrao: {pad.pattern})",
                        caminho=caminho,
                    )
                )
                return

    # ---- callbacks do watchdog ---- #

    def on_created(self, event):
        if event.is_directory:
            return
        self._marca_evento()
        self._checa_extensao(event.src_path)
        self._checa_nota(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._marca_evento()

    def on_moved(self, event):
        if event.is_directory:
            return
        self._marca_evento()
        self._checa_extensao(event.dest_path)
        self._checa_nota(event.dest_path)


# ---------- API publica ---------- #

def _dependencia_ok() -> None:
    if Observer is None:
        raise RuntimeError(
            "Pacote 'watchdog' nao instalado. Rode: pip install watchdog"
        )


def observar(
    pastas: Iterable[Path],
    log_alertas: Path,
    janela_segundos: int = 10,
    limite_eventos: int = 30,
    duracao_segundos: int | None = None,
    stdout: bool = True,
) -> list[AlertaRansom]:
    """
    Observa 'pastas' recursivamente e grita quando o comportamento parecer
    ransomware.

    - janela_segundos: tamanho da janela deslizante.
    - limite_eventos:  quantos eventos nessa janela ja contam como massa.
    - duracao_segundos: None = roda ate Ctrl+C.
    - log_alertas:   arquivo JSONL para gravar cada alerta.

    Retorna os alertas acumulados (uteis quando chamado com duracao finita).
    """
    _dependencia_ok()
    log_alertas.parent.mkdir(parents=True, exist_ok=True)
    alertas: list[AlertaRansom] = []

    def _grava(alerta: AlertaRansom) -> None:
        alertas.append(alerta)
        with open(log_alertas, "a", encoding="utf-8") as f:
            f.write(json.dumps(alerta.dict(), ensure_ascii=False) + "\n")
        if stdout:
            print(
                f"[!!] RANSOM[{alerta.tipo}] {alerta.detalhe}"
                + (f"  arquivo={alerta.caminho}" if alerta.caminho != "(varios)" else "")
            )

    handler = _Handler(janela_segundos, limite_eventos, _grava)
    obs = Observer()

    pastas_ok: list[Path] = []
    for p in pastas:
        p = p.resolve()
        if p.exists() and p.is_dir():
            obs.schedule(handler, str(p), recursive=True)
            pastas_ok.append(p)

    if not pastas_ok:
        raise RuntimeError("Nenhuma pasta valida para observar.")

    if stdout:
        print(f"[i] Observando {len(pastas_ok)} pasta(s). Ctrl+C para parar.")
        for p in pastas_ok:
            print(f"    - {p}")

    obs.start()
    try:
        if duracao_segundos is None:
            while True:
                time.sleep(1)
        else:
            time.sleep(duracao_segundos)
    except KeyboardInterrupt:
        pass
    finally:
        obs.stop()
        obs.join()

    return alertas

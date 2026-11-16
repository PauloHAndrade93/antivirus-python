"""
Network Monitor - deteccao de conexoes suspeitas de saida.

Heuristica defensiva. Nao bloqueia nada: so observa e registra.
Evolucao do 'detector_exfiltracao.py' usado no desafio-malware-simulado.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import psutil

# Portas comuns de C2 / exfiltracao
PORTAS_SMTP = {25, 465, 587}
PORTAS_IRC = {6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 7000}
PORTAS_ALTAS_SUSPEITAS = {4444, 5555, 8888, 1337, 31337}

# Processos que PODEM legitimamente falar SMTP (nao sao alertas)
PROCESSOS_EMAIL_LEGITIMOS = {
    "outlook.exe", "thunderbird.exe", "msedge.exe", "chrome.exe",
    "firefox.exe", "mailbird.exe", "em client.exe",
}


@dataclass
class AlertaRede:
    pid: int
    processo: str
    ip_remoto: str
    porta_remota: int
    motivo: str
    momento: float = field(default_factory=time.time)


def _nome_processo(pid: int) -> str:
    try:
        return (psutil.Process(pid).name() or "?").lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "?"


def _ip_privado(ip: str) -> bool:
    """IPs internos nao sao exfiltracao - pule-os."""
    if ip.startswith(("10.", "127.", "192.168.", "169.254.", "::1", "fe80")):
        return True
    if ip.startswith("172."):
        try:
            segundo = int(ip.split(".")[1])
            return 16 <= segundo <= 31
        except (ValueError, IndexError):
            pass
    return False


def varrer_conexoes_ativas() -> list[AlertaRede]:
    """Snapshot das conexoes de saida atuais com heuristicas aplicadas."""
    alertas: list[AlertaRede] = []

    try:
        conexoes = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # Em Windows, sem admin, net_connections pode falhar
        return alertas

    for c in conexoes:
        if not c.raddr or c.status != psutil.CONN_ESTABLISHED:
            continue
        ip_remoto = c.raddr.ip
        porta = c.raddr.port
        if _ip_privado(ip_remoto):
            continue

        pid = c.pid or 0
        proc = _nome_processo(pid)

        motivo = None
        if porta in PORTAS_SMTP and proc not in PROCESSOS_EMAIL_LEGITIMOS:
            motivo = f"SMTP ({porta}) de processo nao-email: {proc}"
        elif porta in PORTAS_IRC:
            motivo = f"Porta IRC ({porta}) - canal classico de C2"
        elif porta in PORTAS_ALTAS_SUSPEITAS:
            motivo = f"Porta tipicamente usada por RAT/reverse shell ({porta})"

        if motivo:
            alertas.append(AlertaRede(pid, proc, ip_remoto, porta, motivo))

    return alertas


def detectar_beaconing(janela_segundos: int = 90, cadencia_min_conexoes: int = 4) -> list[AlertaRede]:
    """
    Observa a janela e marca processos que abrem conexoes em cadencia regular
    (sinal classico de beaconing C2). Faz amostragem simples.
    """
    amostras: dict[tuple[int, str, int], list[float]] = defaultdict(list)
    fim = time.time() + janela_segundos

    while time.time() < fim:
        try:
            conexoes = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return []
        agora = time.time()
        for c in conexoes:
            if not c.raddr or _ip_privado(c.raddr.ip):
                continue
            chave = (c.pid or 0, c.raddr.ip, c.raddr.port)
            amostras[chave].append(agora)
        time.sleep(5)

    alertas = []
    for (pid, ip, porta), momentos in amostras.items():
        if len(momentos) < cadencia_min_conexoes:
            continue
        # Se o intervalo medio entre amostras eh pequeno e consistente, cheira a beacon
        intervalos = [b - a for a, b in zip(momentos, momentos[1:])]
        if not intervalos:
            continue
        media = sum(intervalos) / len(intervalos)
        if 3 < media < 60:  # janela tipica de beaconing
            alertas.append(
                AlertaRede(
                    pid=pid,
                    processo=_nome_processo(pid),
                    ip_remoto=ip,
                    porta_remota=porta,
                    motivo=f"Beaconing suspeito: {len(momentos)} contatos, media {media:.1f}s",
                )
            )
    return alertas

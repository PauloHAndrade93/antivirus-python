"""
Full Scan - varredura completa de drives (HDs, SSDs, pendrives, cartoes).

Monta a varredura aproveitando os modulos ja existentes:
  - hash_scanner (SHA-256 + lista local + opcional MalwareBazaar/VirusTotal)
  - yara_scanner (regras YARA)

A grande diferenca aqui e a *escala*: ao inves de uma pasta, varre o
disco inteiro, drives removiveis, cartoes. Por isso tem:
  - enumeracao automatica de drives (fixed, removable, cd, network)
  - lista inteligente de EXCLUSOES (pagefile.sys, hiberfil.sys, WinSxS,
    System Volume Information, $Recycle.Bin, Windows\\Installer, etc.)
  - limite de tamanho por arquivo
  - progresso periodico (a cada N arquivos)
  - tratamento robusto de permissao negada e arquivo em uso
  - relatorio final gravado em logs/fullscan_<timestamp>.log
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import psutil


# ---------- enumeracao de drives ---------- #

@dataclass
class Drive:
    letra: str          # "C:\\"
    tipo: str           # "fixed", "removable", "cdrom", "network", "ramdisk"
    fstype: str         # "NTFS", "FAT32", etc.
    rotulo: str = ""


def _tipo_do_drive(opts: str) -> str:
    """psutil coloca o tipo em opts como flag. Mapeia o que importa."""
    o = opts.lower()
    if "removable" in o:
        return "removable"
    if "cdrom" in o:
        return "cdrom"
    if "network" in o or "remote" in o:
        return "network"
    if "ramdisk" in o:
        return "ramdisk"
    return "fixed"


def listar_drives() -> list[Drive]:
    """Lista cada drive montado com tipo (fixo, pendrive, rede, cd)."""
    drives: list[Drive] = []
    for p in psutil.disk_partitions(all=False):
        tipo = _tipo_do_drive(p.opts)
        drives.append(Drive(letra=p.mountpoint, tipo=tipo, fstype=p.fstype))
    return drives


def filtrar_drives(
    drives: list[Drive],
    apenas_usb: bool = False,
    somente_letras: Optional[set[str]] = None,
    pular_rede_e_cd: bool = True,
) -> list[Drive]:
    """Aplica filtros do usuario."""
    out: list[Drive] = []
    for d in drives:
        if apenas_usb and d.tipo != "removable":
            continue
        if pular_rede_e_cd and d.tipo in ("network", "cdrom"):
            continue
        if somente_letras:
            letra = d.letra[:2].upper()
            if letra not in somente_letras:
                continue
        out.append(d)
    return out


# ---------- exclusoes ---------- #

PASTAS_EXCLUIDAS = {
    # Sistema - raramente abriga malware acessivel e e caro varrer
    "windows\\winsxs",
    "windows\\servicing\\lcu",
    "windows\\installer",
    "windows\\system32\\driverstore",
    "windows\\softwaredistribution",
    "program files\\windowsapps",
    "programdata\\package cache",
    "programdata\\microsoft\\windows defender",

    # Lixeira, snapshots e volumes especiais
    "$recycle.bin",
    "system volume information",
    "recovery",
    "config.msi",

    # Quarentena do proprio AV-Py (nao reescaneia)
    "antivirus-python\\quarantine",

    # Virtualizacao e caches de desenvolvimento costumam ser ruidosos
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".cache",
    ".gradle",
    "appdata\\local\\microsoft\\windows\\inetcache",
    "appdata\\local\\microsoft\\edge\\user data\\default\\cache",
    "appdata\\local\\google\\chrome\\user data\\default\\cache",
}

ARQUIVOS_EXCLUIDOS = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "dumpstack.log.tmp", "ntuser.dat",
}


def _deve_pular_pasta(caminho: Path, raiz: Path) -> bool:
    try:
        rel = str(caminho.relative_to(raiz)).lower()
    except ValueError:
        return False
    for excl in PASTAS_EXCLUIDAS:
        if excl in rel:
            return True
    return False


# ---------- progresso ---------- #

@dataclass
class Progresso:
    inicio: float
    total_arquivos: int = 0
    total_hash: int = 0
    total_yara: int = 0
    deteccoes: int = 0
    erros: int = 0

    def resumo(self, rotulo: str = "") -> str:
        elapsed = time.time() - self.inicio
        taxa = self.total_arquivos / elapsed if elapsed > 0 else 0
        return (
            f"[progresso{(' ' + rotulo) if rotulo else ''}] "
            f"{self.total_arquivos} arquivos  "
            f"hash={self.total_hash}  yara={self.total_yara}  "
            f"deteccoes={self.deteccoes}  erros={self.erros}  "
            f"({taxa:.0f} arq/s)"
        )


# ---------- varredura ---------- #

@dataclass
class DeteccaoCompleta:
    arquivo: Path
    motor: str              # "hash", "yara"
    detalhe: str
    sha256: Optional[str] = None


def _iter_arquivos_robusto(raiz: Path, on_erro: Callable[[str], None]) -> Iterable[Path]:
    """
    os.walk com onerror para lidar com permissao negada, e podando as
    pastas excluidas (PASTAS_EXCLUIDAS) *em in-place* para nao descer.
    """
    raiz = Path(raiz)

    def _erro(e):
        on_erro(f"acesso negado: {getattr(e, 'filename', '?')}")

    for dirpath, dirnames, filenames in os.walk(raiz, onerror=_erro):
        dp = Path(dirpath)
        # poda as pastas excluidas
        dirnames[:] = [
            d for d in dirnames
            if not _deve_pular_pasta(dp / d, raiz)
        ]
        for nome in filenames:
            if nome.lower() in ARQUIVOS_EXCLUIDOS:
                continue
            yield dp / nome


def escanear_drive(
    drive: Drive,
    lista_hash_local: set[str],
    api_key_mb: Optional[str],
    ruleset_yara,  # type: ignore[valid-type]
    tamanho_max_mb: int = 100,
    yara_tamanho_max_mb: int = 50,
    intervalo_progresso: int = 500,
    on_progresso: Optional[Callable[[Progresso], None]] = None,
    progresso: Optional[Progresso] = None,
) -> tuple[list[DeteccaoCompleta], Progresso]:
    """
    Varre um drive aplicando hash + YARA. Reutiliza 'progresso' se vier
    (para somar multiplos drives num total unico).
    """
    from .hash_scanner import consultar_malwarebazaar, sha256_do_arquivo

    if progresso is None:
        progresso = Progresso(inicio=time.time())

    deteccoes: list[DeteccaoCompleta] = []
    raiz = Path(drive.letra)
    limite_bytes = tamanho_max_mb * 1024 * 1024
    limite_yara = yara_tamanho_max_mb * 1024 * 1024

    for arquivo in _iter_arquivos_robusto(raiz, lambda m: _conta_erro(progresso, m)):
        try:
            tam = arquivo.stat().st_size
        except (OSError, PermissionError):
            progresso.erros += 1
            continue
        if tam > limite_bytes:
            continue
        progresso.total_arquivos += 1

        # ---- HASH ---- #
        try:
            digest = sha256_do_arquivo(arquivo)
            progresso.total_hash += 1
        except (OSError, PermissionError):
            progresso.erros += 1
            digest = None

        if digest:
            if digest in lista_hash_local:
                progresso.deteccoes += 1
                deteccoes.append(DeteccaoCompleta(
                    arquivo=arquivo, motor="hash",
                    detalhe="hash listado localmente", sha256=digest,
                ))
            elif api_key_mb:
                info = consultar_malwarebazaar(digest, api_key_mb)
                if info:
                    progresso.deteccoes += 1
                    detalhe = f"MalwareBazaar: {info.get('signature', '?')} ({info.get('file_type', '?')})"
                    deteccoes.append(DeteccaoCompleta(
                        arquivo=arquivo, motor="hash",
                        detalhe=detalhe, sha256=digest,
                    ))

        # ---- YARA ---- #
        if ruleset_yara is not None and tam <= limite_yara:
            try:
                matches = ruleset_yara.match(str(arquivo), timeout=20)
                progresso.total_yara += 1
                for m in matches:
                    progresso.deteccoes += 1
                    deteccoes.append(DeteccaoCompleta(
                        arquivo=arquivo, motor="yara",
                        detalhe=f"regra {m.rule} tags={list(m.tags)}",
                    ))
            except (OSError, PermissionError):
                progresso.erros += 1
            except Exception:
                # yara.Error, arquivo bloqueado, etc.
                progresso.erros += 1

        if on_progresso and (progresso.total_arquivos % intervalo_progresso == 0):
            on_progresso(progresso)

    return deteccoes, progresso


def _conta_erro(progresso: Progresso, _msg: str) -> None:
    progresso.erros += 1

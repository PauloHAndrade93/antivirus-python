"""
YARA Scanner - compila regras .yar e varre arquivos.

YARA e a linguagem padrao de pattern matching usada por caca de ameacas
(threat hunting) em todo o setor. Regras publicas:
  - https://github.com/Yara-Rules/rules
  - https://github.com/Neo23x0/signature-base
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import yara  # type: ignore
except ImportError:
    yara = None  # tratado no compilador

from .hash_scanner import iter_arquivos


@dataclass
class MatchYara:
    arquivo: Path
    regra: str
    tags: list[str]
    strings_casadas: list[str]  # nomes dos strings que bateram


def _dependencia_ok() -> None:
    if yara is None:
        raise RuntimeError(
            "Pacote 'yara-python' nao instalado. Rode: pip install yara-python"
        )


def compilar_regras(pasta_regras: Path):
    """Compila todos os .yar/.yara da pasta num unico ruleset."""
    _dependencia_ok()
    arquivos = {}
    for p in pasta_regras.glob("**/*"):
        if p.suffix.lower() in (".yar", ".yara"):
            arquivos[p.stem] = str(p)
    if not arquivos:
        raise RuntimeError(f"Nenhuma regra .yar encontrada em {pasta_regras}")
    return yara.compile(filepaths=arquivos)


def escanear(
    raiz: Path,
    ruleset,
    tamanho_max_mb: int = 100,
) -> list[MatchYara]:
    """Varre arquivos sob 'raiz' aplicando o ruleset compilado."""
    _dependencia_ok()
    matches: list[MatchYara] = []
    limite_bytes = tamanho_max_mb * 1024 * 1024

    for arquivo in iter_arquivos(raiz):
        try:
            if arquivo.stat().st_size > limite_bytes:
                continue
            resultado = ruleset.match(str(arquivo), timeout=30)
        except (OSError, PermissionError):
            continue
        except Exception:
            # yara.Error em arquivo bloqueado, locked, etc.
            continue

        for m in resultado:
            nomes_strings = sorted({s.identifier for s in getattr(m, "strings", [])})
            matches.append(
                MatchYara(
                    arquivo=arquivo,
                    regra=m.rule,
                    tags=list(m.tags),
                    strings_casadas=nomes_strings,
                )
            )

    return matches

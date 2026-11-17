"""
Quarentena - isola arquivos detectados.

Move o arquivo para 'quarantine/', renomeia com timestamp e grava um JSONL
em 'logs/quarantine.log' com metadados (origem, hash, motivo).

Como e uma operacao destrutiva, segue duas regras:
  - dry_run=True simula: diz para onde iria, sem tocar em nada;
  - depois de mover, o SHA-256 e recalculado e comparado com o de antes.
    Se nao bater, o arquivo volta para o lugar e a operacao falha.

NUNCA execute arquivos em quarentena.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

PASTA_QUARENTENA = Path("quarantine")
LOG_QUARENTENA = Path("logs") / "quarantine.log"


class ErroIntegridade(OSError):
    pass


def _sha256(caminho: Path) -> str:
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(64 * 1024), b""):
            h.update(bloco)
    return h.hexdigest()


def _destino_para(origem: Path) -> Path:
    carimbo = time.strftime("%Y%m%d-%H%M%S")
    destino = PASTA_QUARENTENA / f"{carimbo}__{origem.name}.quarantined"
    i = 1
    while destino.exists():
        destino = PASTA_QUARENTENA / f"{carimbo}__{origem.name}.{i}.quarantined"
        i += 1
    return destino


def isolar(origem: Path, motivo: str, sha256: str | None = None, dry_run: bool = False) -> Path:
    """
    Move 'origem' para a quarentena. Retorna o caminho de destino.
    Com dry_run=True, so calcula o destino e nao move nem registra nada.
    """
    destino = _destino_para(origem)
    if dry_run:
        return destino

    PASTA_QUARENTENA.mkdir(parents=True, exist_ok=True)
    LOG_QUARENTENA.parent.mkdir(parents=True, exist_ok=True)

    antes = _sha256(origem)
    shutil.move(str(origem), str(destino))
    depois = _sha256(destino)
    if antes != depois:
        shutil.move(str(destino), str(origem))
        raise ErroIntegridade(f"hash mudou ao mover {origem}; operacao desfeita")

    registro = {
        "momento": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "origem": str(origem),
        "quarentena": str(destino),
        "motivo": motivo,
        "sha256": antes,
        "integridade": "ok",
    }
    if sha256 and sha256 != antes:
        registro["sha256_na_deteccao"] = sha256  # arquivo mudou entre a deteccao e o isolamento
    with open(LOG_QUARENTENA, "a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")

    return destino


def listar() -> list[dict]:
    """Retorna as entradas do log de quarentena, em ordem."""
    if not LOG_QUARENTENA.exists():
        return []
    entradas = []
    with open(LOG_QUARENTENA, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                entradas.append(json.loads(linha))
            except json.JSONDecodeError:
                continue
    return entradas

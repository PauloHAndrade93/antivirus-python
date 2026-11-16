"""
Quarentena - isola arquivos detectados.

Move o arquivo para 'quarantine/', renomeia com timestamp e grava um JSONL
em 'logs/quarantine.log' com metadados (origem, hash, motivo).

NUNCA execute arquivos em quarentena. A pasta deve ficar fora de qualquer
varredura do sistema e sem permissao de execucao, idealmente.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

PASTA_QUARENTENA = Path("quarantine")
LOG_QUARENTENA = Path("logs") / "quarantine.log"


def _preparar_pastas() -> None:
    PASTA_QUARENTENA.mkdir(parents=True, exist_ok=True)
    LOG_QUARENTENA.parent.mkdir(parents=True, exist_ok=True)


def isolar(origem: Path, motivo: str, sha256: str | None = None) -> Path:
    """
    Move 'origem' para a quarentena. Retorna o novo caminho.
    O arquivo isolado ganha extensao .quarantined para evitar execucao acidental.
    """
    _preparar_pastas()
    carimbo = time.strftime("%Y%m%d-%H%M%S")
    destino = PASTA_QUARENTENA / f"{carimbo}__{origem.name}.quarantined"

    # Resolve colisao bobinha
    i = 1
    while destino.exists():
        destino = PASTA_QUARENTENA / f"{carimbo}__{origem.name}.{i}.quarantined"
        i += 1

    shutil.move(str(origem), str(destino))

    registro = {
        "momento": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "origem": str(origem),
        "quarentena": str(destino),
        "motivo": motivo,
        "sha256": sha256,
    }
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

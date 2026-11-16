"""
Hash Scanner - calcula SHA-256 de arquivos e compara contra bases de malware.

Duas fontes:
  1. MalwareBazaar (online, requer chave em MALWAREBAZAAR_API_KEY)
  2. Lista local em rules/hashes_locais.txt (um hash por linha, offline)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import requests

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
CHUNK = 64 * 1024  # 64 KiB por leitura


@dataclass
class Deteccao:
    arquivo: Path
    sha256: str
    fonte: str          # "malwarebazaar" ou "lista_local"
    detalhe: str        # ex.: familia, assinatura, "hash listado"


def sha256_do_arquivo(caminho: Path) -> str:
    """Calcula SHA-256 streaming (seguro para arquivos grandes)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        while True:
            pedaco = f.read(CHUNK)
            if not pedaco:
                break
            h.update(pedaco)
    return h.hexdigest()


def carregar_lista_local(caminho_lista: Path) -> set[str]:
    """Le hashes do arquivo local (um por linha). Retorna set vazio se nao existir."""
    if not caminho_lista.exists():
        return set()
    hashes = set()
    with open(caminho_lista, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip().lower()
            if linha and not linha.startswith("#") and len(linha) == 64:
                hashes.add(linha)
    return hashes


def consultar_malwarebazaar(sha256: str, api_key: str, timeout: int = 10) -> Optional[dict]:
    """
    Consulta o MalwareBazaar pelo hash.
    Retorna dict do malware se encontrado, None se nao estiver na base.
    """
    try:
        resp = requests.post(
            MALWAREBAZAAR_URL,
            data={"query": "get_info", "hash": sha256},
            headers={"Auth-Key": api_key},
            timeout=timeout,
        )
        resp.raise_for_status()
        dados = resp.json()
        if dados.get("query_status") == "ok" and dados.get("data"):
            return dados["data"][0]
        return None
    except (requests.RequestException, ValueError, KeyError):
        # Falha silenciosa: offline, 403, etc. - o scanner continua.
        return None


def iter_arquivos(raiz: Path) -> Iterable[Path]:
    """Percorre recursivamente, pulando quarentena, .git e venvs."""
    EXCLUIR = {".git", "__pycache__", ".venv", "venv", "node_modules", "quarantine"}
    for dirpath, dirnames, filenames in os.walk(raiz):
        dirnames[:] = [d for d in dirnames if d not in EXCLUIR]
        for nome in filenames:
            yield Path(dirpath) / nome


def escanear(
    raiz: Path,
    lista_local: set[str],
    api_key: Optional[str] = None,
    tamanho_max_mb: int = 100,
) -> list[Deteccao]:
    """
    Escaneia uma pasta. Retorna lista de deteccoes.
    Arquivos > tamanho_max_mb sao pulados (performance + MalwareBazaar limita).
    """
    deteccoes: list[Deteccao] = []
    limite_bytes = tamanho_max_mb * 1024 * 1024

    for arquivo in iter_arquivos(raiz):
        try:
            if arquivo.stat().st_size > limite_bytes:
                continue
            digest = sha256_do_arquivo(arquivo)
        except (OSError, PermissionError):
            continue

        # 1. Lista local (rapida, offline)
        if digest in lista_local:
            deteccoes.append(Deteccao(arquivo, digest, "lista_local", "hash listado"))
            continue

        # 2. MalwareBazaar (so se houver chave)
        if api_key:
            info = consultar_malwarebazaar(digest, api_key)
            if info:
                detalhe = f"{info.get('signature', '?')} ({info.get('file_type', '?')})"
                deteccoes.append(Deteccao(arquivo, digest, "malwarebazaar", detalhe))

    return deteccoes

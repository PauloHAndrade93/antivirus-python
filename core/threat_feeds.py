"""
Threat Feeds - baixa feeds gratuitos da abuse.ch e enriquece a base local.

Fontes (gratuitas, exigem uma chave gratuita da abuse.ch unificada):
  - MalwareBazaar: hashes SHA-256 de malware recente
  - URLHaus:       URLs/dominios maliciosos recentes

Em 2024 a abuse.ch passou a exigir uma chave em TODOS os feeds. Cadastro
gratuito em https://auth.abuse.ch/ (a mesma chave vale para MalwareBazaar,
URLHaus, ThreatFox, etc.). Exponha em uma destas variaveis:

    ABUSE_CH_API_KEY   (preferida; usada por todos os feeds)
    MALWAREBAZAAR_API_KEY  (fallback; mesma chave antiga reaproveitada)

Rode periodicamente (ex.: toda semana) com 'python av.py feeds-update'
para o AV-Py detectar malware recem-descoberto mesmo offline.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

import requests

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
# ThreatFox: feed unificado da abuse.ch. Substitui o URLHaus desde que seus
# endpoints publicos foram descontinuados em 2025. Retorna IoCs diversos
# (URLs, dominios, IPs, hashes). Aqui filtramos so as URLs para popular
# rules/urls_maliciosas.txt.
THREATFOX_API     = "https://threatfox-api.abuse.ch/api/v1/"

TIMEOUT = 30


def obter_api_key() -> Optional[str]:
    return os.environ.get("ABUSE_CH_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY")


def _exigir_chave() -> str:
    k = obter_api_key()
    if not k:
        raise RuntimeError(
            "Chave abuse.ch nao configurada. Cadastre em https://auth.abuse.ch/ "
            "e exporte ABUSE_CH_API_KEY (ou MALWAREBAZAAR_API_KEY)."
        )
    return k


def atualizar_malwarebazaar(destino: Path, selector: str = "100") -> tuple[int, int]:
    """
    Baixa os hashes das amostras recentes via API v1.
    selector: 'time' (ultima hora) ou um numero ('100', '1000'...).
    Retorna (adicionados, total_final).
    """
    key = _exigir_chave()
    resp = requests.post(
        MALWAREBAZAAR_API,
        data={"query": "get_recent", "selector": selector},
        headers={"Auth-Key": key},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("query_status") != "ok":
        raise RuntimeError(f"MalwareBazaar: query_status={payload.get('query_status')}")

    novos: set[str] = set()
    for item in payload.get("data", []):
        h = (item.get("sha256_hash") or "").lower()
        if len(h) == 64:
            novos.add(h)

    existentes: set[str] = set()
    cabecalho: list[str] = []
    if destino.exists():
        for linha in destino.read_text(encoding="utf-8").splitlines():
            if linha.strip().startswith("#"):
                cabecalho.append(linha)
                continue
            v = linha.strip().lower()
            if len(v) == 64:
                existentes.add(v)

    tamanho_antes = len(existentes)
    todos = existentes | novos
    adicionados = len(todos) - tamanho_antes

    if not cabecalho:
        cabecalho = [
            "# Lista local de hashes SHA-256 de malware conhecido.",
            "# Alimentada por 'av.py feeds-update' (abuse.ch MalwareBazaar).",
            "",
        ]
    destino.write_text(
        "\n".join(cabecalho) + "\n" + "\n".join(sorted(todos)) + "\n",
        encoding="utf-8",
    )
    return adicionados, len(todos)


def atualizar_urlhaus(destino: Path, dias: int = 1) -> tuple[int, int]:
    """
    Baixa URLs maliciosas recentes do ThreatFox (abuse.ch).
    Retorna (adicionadas, total_final).
    """
    key = _exigir_chave()
    resp = requests.post(
        THREATFOX_API,
        json={"query": "get_iocs", "days": dias},
        headers={"Auth-Key": key},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: query_status={payload.get('query_status')}")

    novas: set[str] = set()
    for item in payload.get("data", []):
        ioc_type = (item.get("ioc_type") or "").lower()
        ioc = (item.get("ioc") or "").strip()
        if ioc_type == "url" and ioc.startswith(("http://", "https://")):
            novas.add(ioc)
        elif ioc_type in ("domain", "url") and "." in ioc:
            # tambem aceita dominio puro - prefixa http://
            if not ioc.startswith(("http://", "https://")):
                novas.add("http://" + ioc)

    existentes: set[str] = set()
    if destino.exists():
        for linha in destino.read_text(encoding="utf-8").splitlines():
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                existentes.add(linha)

    tamanho_antes = len(existentes)
    todas = existentes | novas
    adicionadas = len(todas) - tamanho_antes

    destino.write_text(
        "# URLs maliciosas (abuse.ch URLHaus feed recente).\n"
        "# Alimentada por 'av.py feeds-update'.\n\n"
        + "\n".join(sorted(todas)) + "\n",
        encoding="utf-8",
    )
    return adicionadas, len(todas)


def dominios_urlhaus(path: Path) -> set[str]:
    """Extrai os dominios distintos da lista de URLs do URLHaus."""
    if not path.exists():
        return set()
    import urllib.parse as up
    dominios: set[str] = set()
    for linha in path.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        try:
            p = up.urlparse(linha)
            if p.hostname:
                dominios.add(p.hostname.lower())
        except ValueError:
            continue
    return dominios

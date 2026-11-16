"""
VirusTotal lookup - cliente simples da API v3.

VirusTotal roda cada amostra por 70+ antivirus e publica o veredito
consolidado. Para o AV-Py, ele serve como "segunda opiniao": quando o
scanner local nao conhece um hash, a gente pode perguntar ao VT se ele
ja viu aquele arquivo e quantos engines marcaram como malicioso.

Esta implementacao suporta:
  - hash  (SHA-256, SHA-1 ou MD5)
  - IP    (IPv4)
  - dominio

Precisa de uma chave de API gratuita em https://www.virustotal.com/gui/my-apikey
e expo-la na variavel de ambiente VT_API_KEY.

Limite da conta gratuita: 4 requisicoes por minuto, 500 por dia.
Este cliente respeita o limite por minuto com um sleep simples.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 15

# ---------- rate limit simples (4 req / minuto) ---------- #

_LOCK = threading.Lock()
_ULTIMA_REQ: list[float] = []  # timestamps na janela de 60s


def _respeitar_limite(max_por_minuto: int = 4) -> None:
    with _LOCK:
        agora = time.time()
        corte = agora - 60
        # descarta chamadas que sairam da janela
        del _ULTIMA_REQ[:]
        _ULTIMA_REQ.extend(t for t in _ULTIMA_REQ if t >= corte)
        if len(_ULTIMA_REQ) >= max_por_minuto:
            espera = 60 - (agora - _ULTIMA_REQ[0]) + 0.1
            if espera > 0:
                time.sleep(espera)
        _ULTIMA_REQ.append(time.time())


# ---------- veredito ---------- #

@dataclass
class Veredito:
    tipo: str          # "hash", "ip", "dominio"
    chave: str
    malicioso: int = 0
    suspeito: int = 0
    inofensivo: int = 0
    nao_detectado: int = 0
    engines_total: int = 0
    conhecido: bool = False
    rotulo: Optional[str] = None   # nome sugerido pela comunidade, se houver
    erro: Optional[str] = None     # "sem chave", "quota", "nao encontrado", etc.

    @property
    def nivel(self) -> str:
        if self.erro:
            return "erro"
        if not self.conhecido:
            return "desconhecido"
        if self.malicioso >= 5:
            return "malicioso"
        if self.malicioso >= 1 or self.suspeito >= 3:
            return "suspeito"
        return "limpo"

    def resumo(self) -> str:
        if self.erro:
            return f"VT {self.tipo} {self.chave}: ERRO - {self.erro}"
        if not self.conhecido:
            return f"VT {self.tipo} {self.chave}: desconhecido (nunca visto no VT)"
        linha = (
            f"VT {self.tipo} {self.chave}: {self.nivel.upper()}  "
            f"(malicioso={self.malicioso} / total={self.engines_total})"
        )
        if self.rotulo:
            linha += f"  rotulo='{self.rotulo}'"
        return linha


# ---------- helpers ---------- #

def _is_hash(valor: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32,64}", valor)) and len(valor) in (32, 40, 64)


def _is_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def _is_dominio(valor: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}", valor))


def detectar_tipo(valor: str) -> Optional[str]:
    v = valor.strip().lower()
    if _is_hash(v):
        return "hash"
    if _is_ip(v):
        return "ip"
    if _is_dominio(v):
        return "dominio"
    return None


# ---------- consulta ---------- #

def _get(url: str, api_key: str) -> tuple[int, dict]:
    _respeitar_limite()
    resp = requests.get(url, headers={"x-apikey": api_key}, timeout=TIMEOUT)
    try:
        dados = resp.json()
    except ValueError:
        dados = {}
    return resp.status_code, dados


def _construir_veredito(
    tipo: str, chave: str, codigo: int, dados: dict
) -> Veredito:
    v = Veredito(tipo=tipo, chave=chave)
    if codigo == 401:
        v.erro = "chave VT_API_KEY invalida"
        return v
    if codigo == 429:
        v.erro = "quota excedida (4/min ou 500/dia)"
        return v
    if codigo == 404:
        return v  # nao conhecido
    if codigo != 200:
        v.erro = f"HTTP {codigo}"
        return v

    atributos = (dados.get("data") or {}).get("attributes") or {}
    stats = atributos.get("last_analysis_stats") or {}
    v.conhecido = bool(stats)
    v.malicioso = int(stats.get("malicious", 0))
    v.suspeito = int(stats.get("suspicious", 0))
    v.inofensivo = int(stats.get("harmless", 0))
    v.nao_detectado = int(stats.get("undetected", 0))
    v.engines_total = sum(stats.values())

    # rotulo da comunidade (popular_threat_name)
    classif = atributos.get("popular_threat_classification") or {}
    rotulo = classif.get("suggested_threat_label")
    if rotulo:
        v.rotulo = rotulo
    return v


def consultar_hash(sha256: str, api_key: str) -> Veredito:
    if not api_key:
        return Veredito(tipo="hash", chave=sha256, erro="sem chave (VT_API_KEY)")
    codigo, dados = _get(f"{BASE_URL}/files/{sha256}", api_key)
    return _construir_veredito("hash", sha256, codigo, dados)


def consultar_ip(ip: str, api_key: str) -> Veredito:
    if not api_key:
        return Veredito(tipo="ip", chave=ip, erro="sem chave (VT_API_KEY)")
    codigo, dados = _get(f"{BASE_URL}/ip_addresses/{ip}", api_key)
    return _construir_veredito("ip", ip, codigo, dados)


def consultar_dominio(dominio: str, api_key: str) -> Veredito:
    if not api_key:
        return Veredito(tipo="dominio", chave=dominio, erro="sem chave (VT_API_KEY)")
    codigo, dados = _get(f"{BASE_URL}/domains/{dominio}", api_key)
    return _construir_veredito("dominio", dominio, codigo, dados)


def consultar_auto(valor: str, api_key: str) -> Veredito:
    """Detecta o tipo e dispara a consulta certa."""
    tipo = detectar_tipo(valor)
    if tipo == "hash":
        return consultar_hash(valor.lower(), api_key)
    if tipo == "ip":
        return consultar_ip(valor, api_key)
    if tipo == "dominio":
        return consultar_dominio(valor.lower(), api_key)
    return Veredito(
        tipo="?", chave=valor,
        erro="entrada nao reconhecida como hash/IP/dominio",
    )

"""
Hosts Integrity - audita o arquivo hosts do Windows.

Malware mexe no C:\\Windows\\System32\\drivers\\etc\\hosts para:
  - Bloquear antivirus, Windows Update e feeds de ameaca
  - Redirecionar bancos e carteiras cripto para IPs proprios (pharming)
  - Interceptar servicos de atualizacao de software

Esta auditoria so le o arquivo (nao modifica) e sinaliza linhas suspeitas.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\drivers\etc\hosts"

IPS_BLOQUEIO = ("0.0.0.0", "127.0.0.1", "127.0.0.2", "::1", "::")

# Os nomes precisam aparecer como "pedaco" do dominio (entre pontos ou hifens).
# Antes era busca por substring: 'preset.example' casava 'eset' e
# 'nextcloud.lan' casava o banco 'next'. Os testes cobrem esses casos.
DOMINIOS_SECURITY_BLOQUEIO = re.compile(
    r"(^|[.-])(microsoft|windowsupdate|defender|smartscreen|"
    r"avast|avg|avira|bitdefender|eset|kaspersky|mcafee|norton|sophos|"
    r"trendmicro|malwarebytes|virustotal|abuse|crowdstrike|"
    r"sentinelone|carbonblack)([.-]|$)",
    re.I,
)

DOMINIOS_FINANCEIROS = re.compile(
    r"(^|\.)(bb\.com\.br|bancobrasil|itau|bradesco|santander|caixa|"
    r"nubank|bancointer|inter\.co|c6bank|banconext|neon|picpay|"
    r"paypal|mercadopago|pagseguro|"
    r"binance|coinbase|kraken|bitfinex|mercadobitcoin|foxbit)(\.|$)",
    re.I,
)


@dataclass
class HostsAlerta:
    tipo: str          # "bloqueio_security", "hijack_financeiro", "erro"
    numero_linha: int
    linha: str
    detalhe: str


def auditar(path: Path | None = None) -> list[HostsAlerta]:
    caminho = path or HOSTS_PATH
    alertas: list[HostsAlerta] = []

    if not caminho.exists():
        return [HostsAlerta(
            tipo="erro", numero_linha=0, linha="",
            detalhe=f"arquivo nao encontrado: {caminho}",
        )]

    try:
        conteudo = caminho.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return [HostsAlerta(
            tipo="erro", numero_linha=0, linha="",
            detalhe="sem permissao de leitura (tente rodar como admin)",
        )]

    for n, raw in enumerate(conteudo.splitlines(), 1):
        linha = raw.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split()
        if len(partes) < 2:
            continue

        ip, host = partes[0], partes[1]
        host_lower = host.lower()

        # 1) bloqueio de servico de seguranca
        if ip in IPS_BLOQUEIO and DOMINIOS_SECURITY_BLOQUEIO.search(host_lower):
            alertas.append(HostsAlerta(
                tipo="bloqueio_security", numero_linha=n, linha=linha,
                detalhe=f"bloqueio de servico de seguranca: {host}",
            ))

        # 2) hijack financeiro: dominio bancario/cripto apontando para IP externo
        if ip not in IPS_BLOQUEIO and DOMINIOS_FINANCEIROS.search(host_lower):
            alertas.append(HostsAlerta(
                tipo="hijack_financeiro", numero_linha=n, linha=linha,
                detalhe=f"dominio financeiro redirecionado: {host} -> {ip} (pharming?)",
            ))

    return alertas

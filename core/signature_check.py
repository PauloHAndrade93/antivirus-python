"""
Signature Check - verifica assinatura Authenticode no Windows.

Usado como whitelist no fullscan: se um executavel esta assinado por um
publisher confiavel (Microsoft, Google, Mozilla, Steam, etc.), um match
YARA sobre ele vira 'ignorado por assinatura' em vez de alerta.

Chama PowerShell Get-AuthenticodeSignature por arquivo. Por isso so e
acionado DEPOIS de YARA bater - uma chamada PS leva ~300ms e nao faz
sentido rodar em 7000+ arquivos.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PUBLISHERS_CONFIAVEIS = {
    "microsoft corporation", "microsoft windows", "microsoft windows publisher",
    "microsoft marketplace",
    "google llc", "google inc", "mozilla corporation", "apple inc.",
    "adobe systems incorporated", "adobe inc.", "oracle america, inc.",
    "intel corporation", "nvidia corporation",
    "advanced micro devices, inc.", "amd", "realtek semiconductor corp.",
    "docker inc", "docker, inc.",
    "valve", "riot games, inc.", "epic games, inc.",
    "github, inc.", "python software foundation", "jetbrains s.r.o.",
    "autodesk, inc.", "logitech inc", "steelseries aps",
    "whatsapp llc", "spotify ab", "zoom video communications, inc.",
    "igor pavlov", "videolan", "canonical", "red hat",
    "open source developer, paulo",  # desenvolvedores comuns do seu PC - ajuste
}

EXT_EXECUTAVEIS = {".exe", ".dll", ".sys", ".msi", ".ocx", ".cpl", ".drv", ".scr"}


@dataclass
class Assinatura:
    status: str                    # "valida", "nao_assinada", "invalida", "desconhecida", "erro", "nao_aplica"
    publisher: Optional[str] = None
    confiavel: bool = False


def verificar(caminho: Path, timeout: int = 10) -> Assinatura:
    """Retorna o status da assinatura do arquivo (somente Windows)."""
    if caminho.suffix.lower() not in EXT_EXECUTAVEIS:
        return Assinatura(status="nao_aplica")

    try:
        ps = (
            f"$ErrorActionPreference='SilentlyContinue'; "
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{caminho}'; "
            "Write-Output $sig.Status.ToString(); "
            "if ($sig.SignerCertificate) { Write-Output $sig.SignerCertificate.Subject }"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return Assinatura(status="erro")

    stdout = res.stdout.decode("cp1252", errors="replace").strip().splitlines()
    if not stdout:
        return Assinatura(status="erro")

    status_raw = stdout[0].strip().lower()
    subject = stdout[1].strip() if len(stdout) > 1 else None

    publisher = None
    if subject:
        for parte in subject.split(","):
            parte = parte.strip()
            if parte.upper().startswith("CN="):
                publisher = parte[3:]
                break

    status_map = {
        "valid":              "valida",
        "notsigned":          "nao_assinada",
        "hashmismatch":       "invalida",
        "notsupportedfiletype": "nao_aplica",
        "unknownerror":       "desconhecida",
    }
    status = status_map.get(status_raw, status_raw or "desconhecida")

    confiavel = False
    if status == "valida" and publisher:
        p = publisher.lower()
        confiavel = any(pub in p for pub in PUBLISHERS_CONFIAVEIS)

    return Assinatura(status=status, publisher=publisher, confiavel=confiavel)

"""
Process Scanner - audita processos em execucao.

Heuristicas:
  - Executaveis rodando de %TEMP%, %APPDATA%\\Local\\Temp, Downloads, Public
  - Interpretadores (powershell, cmd, wscript, mshta, rundll32, ...) com pai
    tipico de malware (Office, Outlook, Acrobat) - padrao LOLBAS classico
  - Executaveis sem extensao ou com extensao dupla (tipo arquivo.pdf.exe)
  - Processo com nome igual ao de um servico do sistema mas rodando de
    fora de C:\\Windows (impersonacao)

Nao mata processos. So detecta e lista.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil


PASTAS_SUSPEITAS = [re.compile(p, re.I) for p in [
    r"\\AppData\\Local\\Temp\\",
    r"\\Users\\Public\\",
    r"\\Users\\[^\\]+\\Downloads\\",
    r"\\Windows\\Temp\\",
    r"\\Recycle",
]]

INTERPRETADORES = {
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "curl.exe",
}

PAIS_SUSPEITOS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe",
    "outlook.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe",
    "thunderbird.exe", "mailbird.exe",
}

NOMES_SISTEMA_IMPERSONADOS = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "wininit.exe", "explorer.exe", "spoolsv.exe",
    "smss.exe", "taskhost.exe", "taskhostw.exe",
}


@dataclass
class AlertaProc:
    pid: int
    nome: str
    caminho: str
    pai_nome: str
    pai_pid: int
    sinais: list[str] = field(default_factory=list)


def _nome_processo(pid: int) -> str:
    try:
        return (psutil.Process(pid).name() or "?").lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "?"


def auditar() -> list[AlertaProc]:
    alertas: list[AlertaProc] = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "ppid"]):
        try:
            info = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        pid = info.get("pid") or 0
        nome = (info.get("name") or "?").lower()
        exe = info.get("exe") or ""
        ppid = info.get("ppid") or 0
        pai_nome = _nome_processo(ppid)

        sinais: list[str] = []

        # 1) pasta de execucao suspeita
        if exe:
            for pad in PASTAS_SUSPEITAS:
                if pad.search(exe):
                    sinais.append(f"executa de {pad.pattern}")
                    break

        # 2) interpretador com pai de Office/Mail/Acrobat (LOLBAS)
        if nome in INTERPRETADORES and pai_nome in PAIS_SUSPEITOS:
            sinais.append(f"interpretador '{nome}' iniciado por '{pai_nome}' (LOLBAS classico)")

        # 3) impersonacao: nome de servico do Windows rodando fora de C:\Windows
        if nome in NOMES_SISTEMA_IMPERSONADOS and exe:
            if not exe.lower().startswith(("c:\\windows", r"c:\windows")):
                sinais.append(f"nome '{nome}' mas executa de {exe} (impersonacao?)")

        # 4) extensao dupla (arquivo.pdf.exe, nota.doc.exe, ...)
        p_nome = Path(exe).name.lower() if exe else nome
        partes = p_nome.split(".")
        if len(partes) >= 3 and partes[-2] in ("pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "zip"):
            sinais.append(f"extensao dupla suspeita: {p_nome}")

        if sinais:
            alertas.append(AlertaProc(
                pid=pid, nome=nome, caminho=exe,
                pai_nome=pai_nome, pai_pid=ppid, sinais=sinais,
            ))

    return alertas

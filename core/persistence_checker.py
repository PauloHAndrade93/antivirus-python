"""
Persistence Checker - enumera e sinaliza pontos de persistencia no Windows.

Malware precisa sobreviver ao reboot. Ha pouquissimos lugares onde isso cabe:
  1) Chaves "Run" do Registro (HKLM e HKCU)
  2) Pastas Startup (do usuario e de todos os usuarios)
  3) Tarefas agendadas (Scheduled Tasks)
  4) Servicos com inicio automatico

Este modulo lista cada ponto e marca os itens suspeitos por heuristica
(localizacao em %TEMP% / %APPDATA%\\Local\\Temp, comando com powershell
codificado, binario em pasta de download, etc). Nao remove nada - ao
confirmar algo suspeito, o usuario decide o que fazer.

Mapeamento MITRE ATT&CK:
  T1547.001  Registry Run Keys / Startup Folder
  T1053.005  Scheduled Task
  T1543.003  Windows Service
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    import winreg  # Windows only
except ImportError:
    winreg = None  # type: ignore


# ---------- padroes heuristicos ---------- #

PASTAS_SUSPEITAS = [
    re.compile(r"\\AppData\\Local\\Temp\\", re.I),
    re.compile(r"\\Temp\\", re.I),
    re.compile(r"\\Downloads\\", re.I),
    re.compile(r"\\Users\\Public\\", re.I),
    re.compile(r"\\ProgramData\\(?!(Microsoft|Package Cache|chocolatey|NVIDIA|Intel|Apple))", re.I),
    re.compile(r"\\Recycle", re.I),
]

PADROES_COMANDO_SUSPEITO = [
    re.compile(r"powershell.*-encodedcommand", re.I),
    re.compile(r"powershell.*-w\s+hidden", re.I),
    re.compile(r"powershell.*-enc\b", re.I),
    re.compile(r"powershell.*-nop.*-ep\s+bypass", re.I),
    re.compile(r"mshta\s+http", re.I),
    re.compile(r"rundll32\s+javascript:", re.I),
    re.compile(r"regsvr32\s+/s\s+/n\s+/u\s+/i:http", re.I),  # Squiblydoo
    re.compile(r"cmd.*\/c\s+start\s+http", re.I),
    re.compile(r"\bcertutil\b.*-urlcache.*-f", re.I),
    re.compile(r"\bbitsadmin\b.*\/transfer", re.I),
    re.compile(r"\bcurl\b.*\s-o\s", re.I),
    re.compile(r"\bwget\b", re.I),
    re.compile(r"iex\s*\(", re.I),
    re.compile(r"invoke-expression", re.I),
]


# ---------- modelo ---------- #

@dataclass
class ItemPersistencia:
    categoria: str          # "registry", "startup", "tarefa", "servico"
    nome: str
    localizacao: str        # chave ou pasta ou caminho
    comando: str
    sinais: list[str] = field(default_factory=list)

    @property
    def suspeito(self) -> bool:
        return bool(self.sinais)

    def dict(self) -> dict:
        return {
            "categoria": self.categoria,
            "nome": self.nome,
            "localizacao": self.localizacao,
            "comando": self.comando,
            "sinais": self.sinais,
            "suspeito": self.suspeito,
        }


# ---------- heuristicas ---------- #

def _sinais_para(comando: str) -> list[str]:
    s: list[str] = []
    for pad in PASTAS_SUSPEITAS:
        if pad.search(comando):
            s.append(f"caminho em area temporaria/download ({pad.pattern})")
            break
    for pad in PADROES_COMANDO_SUSPEITO:
        if pad.search(comando):
            s.append(f"padrao LOLBAS/dropper ({pad.pattern})")
    if comando.count("'") + comando.count('"') >= 6:
        s.append("muitas aspas (possivel ofuscacao)")
    if any(b64 in comando for b64 in ("==", "FromBase64String", "frombase64string")):
        s.append("possivel conteudo base64 embutido")
    return s


# ---------- registry ---------- #

CHAVES_RUN = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def _abrir_raiz(nome: str):
    if winreg is None:
        return None
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[nome]


def verificar_registry() -> list[ItemPersistencia]:
    """Enumera as chaves Run/RunOnce."""
    if winreg is None:
        return []
    achados: list[ItemPersistencia] = []
    for raiz_nome, subchave in CHAVES_RUN:
        raiz = _abrir_raiz(raiz_nome)
        try:
            with winreg.OpenKey(raiz, subchave) as k:
                i = 0
                while True:
                    try:
                        nome, valor, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    cmd = str(valor)
                    achados.append(
                        ItemPersistencia(
                            categoria="registry",
                            nome=nome,
                            localizacao=f"{raiz_nome}\\{subchave}",
                            comando=cmd,
                            sinais=_sinais_para(cmd),
                        )
                    )
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return achados


# ---------- pastas startup ---------- #

def _pastas_startup() -> list[Path]:
    candidatos = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("ProgramData")
    if appdata:
        candidatos.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
    if programdata:
        candidatos.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\StartUp")
    return [p for p in candidatos if p.exists()]


def verificar_startup() -> list[ItemPersistencia]:
    achados: list[ItemPersistencia] = []
    for pasta in _pastas_startup():
        try:
            for item in pasta.iterdir():
                if item.is_file():
                    cmd = str(item)
                    achados.append(
                        ItemPersistencia(
                            categoria="startup",
                            nome=item.name,
                            localizacao=str(pasta),
                            comando=cmd,
                            sinais=_sinais_para(cmd),
                        )
                    )
        except PermissionError:
            continue
    return achados


# ---------- tarefas agendadas ---------- #

def verificar_tarefas() -> list[ItemPersistencia]:
    """
    Lista tarefas agendadas via schtasks /query /fo CSV /v.
    Ignora tarefas em \\Microsoft\\ (sistema) para focar no que foi criado
    depois - malware raramente cria subpastas dentro de \\Microsoft\\.
    """
    try:
        res = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v", "/nh"],
            capture_output=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    # schtasks solta bytes na codepage local, com algumas sujeiras binarias
    # em instalacoes mistas. decoda tolerante.
    stdout = res.stdout.decode("cp1252", errors="replace") if res.stdout else ""

    achados: list[ItemPersistencia] = []
    for linha in stdout.splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("INFO:"):
            continue
        # CSV com aspas. Faz um parse bobinho (schtasks separa com virgula)
        partes = _csv_split(linha)
        if len(partes) < 10:
            continue
        nome = partes[1].strip('"')
        acao = partes[8].strip('"')  # "Task To Run"
        if nome.startswith("\\Microsoft\\"):
            continue
        if not acao or acao == "N/A" or acao == "COM handler":
            continue
        achados.append(
            ItemPersistencia(
                categoria="tarefa",
                nome=nome,
                localizacao="Scheduled Tasks",
                comando=acao,
                sinais=_sinais_para(acao),
            )
        )
    return achados


def _csv_split(linha: str) -> list[str]:
    """Parse de CSV com aspas, suficiente para a saida do schtasks."""
    partes = []
    atual = []
    dentro_aspas = False
    for c in linha:
        if c == '"':
            dentro_aspas = not dentro_aspas
            atual.append(c)
        elif c == "," and not dentro_aspas:
            partes.append("".join(atual))
            atual = []
        else:
            atual.append(c)
    partes.append("".join(atual))
    return partes


# ---------- servicos ---------- #

def verificar_servicos() -> list[ItemPersistencia]:
    """
    Servicos com inicio automatico lidos do registro.
    Chave: HKLM\\SYSTEM\\CurrentControlSet\\Services.
    Start = 2 significa 'Auto'.
    """
    if winreg is None:
        return []
    achados: list[ItemPersistencia] = []
    try:
        raiz = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"
        )
    except OSError:
        return []

    i = 0
    while True:
        try:
            subnome = winreg.EnumKey(raiz, i)
        except OSError:
            break
        i += 1
        try:
            with winreg.OpenKey(raiz, subnome) as sk:
                try:
                    start, _ = winreg.QueryValueEx(sk, "Start")
                except FileNotFoundError:
                    continue
                if start != 2:
                    continue
                try:
                    image, _ = winreg.QueryValueEx(sk, "ImagePath")
                except FileNotFoundError:
                    continue
                cmd = str(image)
                sinais = _sinais_para(cmd)
                # Servico padrao do Windows nao mora em pasta de usuario
                if re.search(r"\\Users\\", cmd, re.I):
                    sinais.append("servico apontando para pasta de usuario")
                if not sinais:
                    continue  # ignora os milhares de servicos normais do Windows
                achados.append(
                    ItemPersistencia(
                        categoria="servico",
                        nome=subnome,
                        localizacao=r"HKLM\SYSTEM\CurrentControlSet\Services",
                        comando=cmd,
                        sinais=sinais,
                    )
                )
        except OSError:
            continue
    return achados


# ---------- orquestracao ---------- #

def verificar_tudo() -> dict[str, list[ItemPersistencia]]:
    return {
        "registry": verificar_registry(),
        "startup": verificar_startup(),
        "tarefa": verificar_tarefas(),
        "servico": verificar_servicos(),
    }


def apenas_suspeitos(resultado: dict[str, list[ItemPersistencia]]) -> list[ItemPersistencia]:
    out: list[ItemPersistencia] = []
    for itens in resultado.values():
        out.extend(x for x in itens if x.suspeito)
    return out

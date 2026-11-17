"""
Quarentena e uma operacao destrutiva (move arquivos). Por isso:
  - existe um modo de simulacao (dry-run) que nao toca em nada;
  - depois de mover, o hash e conferido de novo (o "oraculo" diz se deu certo).
"""

import hashlib
import json

import pytest

from core import quarantine


@pytest.fixture
def pastas(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine, "PASTA_QUARENTENA", tmp_path / "quarantine")
    monkeypatch.setattr(quarantine, "LOG_QUARENTENA", tmp_path / "logs" / "quarantine.log")
    return tmp_path


def test_isolar_move_renomeia_e_registra(pastas):
    alvo = pastas / "suspeito.exe"
    alvo.write_bytes(b"binario de teste")

    destino = quarantine.isolar(alvo, motivo="teste")

    assert not alvo.exists()
    assert destino.exists()
    assert destino.name.endswith(".quarantined")
    registro = quarantine.listar()[-1]
    assert registro["origem"] == str(alvo)
    assert registro["sha256"] == hashlib.sha256(b"binario de teste").hexdigest()
    assert registro["integridade"] == "ok"


def test_dry_run_nao_move_nem_registra(pastas):
    alvo = pastas / "suspeito.exe"
    alvo.write_bytes(b"binario de teste")

    destino = quarantine.isolar(alvo, motivo="teste", dry_run=True)

    assert alvo.exists()
    assert not destino.exists()
    assert quarantine.listar() == []


def test_dois_arquivos_com_mesmo_nome_nao_colidem(pastas):
    a = pastas / "a" / "x.exe"
    b = pastas / "b" / "x.exe"
    for p, conteudo in ((a, b"um"), (b, b"dois")):
        p.parent.mkdir()
        p.write_bytes(conteudo)

    d1 = quarantine.isolar(a, motivo="t")
    d2 = quarantine.isolar(b, motivo="t")

    assert d1 != d2
    assert d1.read_bytes() == b"um"
    assert d2.read_bytes() == b"dois"


def test_log_corrompido_nao_quebra_listagem(pastas):
    quarantine.LOG_QUARENTENA.parent.mkdir(parents=True)
    quarantine.LOG_QUARENTENA.write_text(
        "isso nao e json\n" + json.dumps({"origem": "x"}) + "\n", encoding="utf-8"
    )
    assert quarantine.listar() == [{"origem": "x"}]

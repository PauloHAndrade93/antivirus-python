"""
O painel dispara varreduras no computador. Estes testes garantem que as
protecoes continuam de pe: so localhost, token obrigatorio, lista branca.
"""

import pytest

pytest.importorskip("flask")

from web import app as painel  # noqa: E402

BASE = f"http://127.0.0.1:{painel.PORTA}"


@pytest.fixture
def cliente():
    return painel.app.test_client()


def test_pagina_abre_com_csp(cliente):
    r = cliente.get("/", base_url=BASE)
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_host_desconhecido_e_bloqueado(cliente):
    """Protecao contra DNS rebinding."""
    assert cliente.get("/api/status", base_url="http://evil.example:8765").status_code == 403


def test_post_sem_token_e_bloqueado(cliente):
    r = cliente.post("/api/jobs", json={"acao": "procs"}, base_url=BASE)
    assert r.status_code == 403


def test_post_de_outra_origem_e_bloqueado(cliente):
    r = cliente.post(
        "/api/jobs", json={"acao": "procs"}, base_url=BASE,
        headers={"X-AVPY-Token": painel.TOKEN, "Origin": "http://evil.example"},
    )
    assert r.status_code == 403


def test_acao_desconhecida_e_recusada(cliente):
    r = cliente.post(
        "/api/jobs", json={"acao": "del", "params": {}}, base_url=BASE,
        headers={"X-AVPY-Token": painel.TOKEN},
    )
    assert r.status_code == 400


def test_relatorio_nao_permite_sair_da_pasta(cliente):
    assert cliente.get("/api/relatorios/..%5Cav.py", base_url=BASE).status_code == 404
    assert cliente.get("/api/relatorios/../av.py", base_url=BASE).status_code == 404


def test_status_nunca_expoe_valor_das_chaves(cliente, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "segredo-de-teste")
    r = cliente.get("/api/status", base_url=BASE)
    assert r.status_code == 200
    assert "segredo-de-teste" not in r.get_data(as_text=True)
    assert set(r.get_json()["chaves"].values()) <= {True, False}


# ------------------------------------------------------------ lista branca de parametros

@pytest.mark.parametrize("acao,params", [
    ("scan", {"pasta": "-rf"}),
    ("scan", {"pasta": "C:/pasta/que/nao/existe/xyz"}),
    ("fullscan", {"drive": "C: & del *"}),
    ("vt", {"alvos": "a b c d e"}),
    ("vt", {"alvos": "isso-nao-e-nada"}),
    ("netmon", {"beacon": True, "janela": "999999"}),
    ("watch", {"pastas": "C:/pasta/que/nao/existe/xyz", "duracao": 60}),
])
def test_parametros_invalidos_sao_recusados(acao, params):
    with pytest.raises(ValueError):
        painel.montar_argv(acao, params)


def test_scan_valido_com_simulacao(tmp_path):
    argv = painel.montar_argv("scan", {"pasta": str(tmp_path), "quarantine": True, "dry_run": True})
    assert argv == ["scan", str(tmp_path), "--quarantine", "--dry-run"]


def test_fullscan_com_drive(tmp_path):
    argv = painel.montar_argv("fullscan", {"drive": "E:"})
    assert argv[argv.index("--drive") + 1] == "E:"

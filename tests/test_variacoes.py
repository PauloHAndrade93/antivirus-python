"""
Variacoes geradas automaticamente (property-based testing com Hypothesis).

Um teste comum verifica UM caso. Aqui cada teste descreve uma PROPRIEDADE
("qualquer letra de drive, escrita de qualquer jeito, vira 'X:'") e o
Hypothesis gera centenas de variacoes para tentar quebra-la. Quando acha
uma, ele reduz ao menor exemplo que falha e guarda em .hypothesis/ para
repetir sempre - vira um teste de regressao automatico.

E a ideia do podcast levada ao extremo: nao so "o bug que a pessoa achou
nao volta", mas "as N formas parecidas desse bug tambem nao".
"""

import hashlib
import os
import string
import tempfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from core import full_scan, hash_scanner, hosts_integrity, process_scanner, quarantine  # noqa: E402

# 300 variacoes por teste normalmente; o hook do agente usa menos (AVPY_VARIACOES) para ser rapido.
VARIACOES = settings(
    max_examples=int(os.environ.get("AVPY_VARIACOES", "300")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

letras = st.sampled_from(string.ascii_letters)
separadores = st.text(alphabet=": \\/", max_size=4)


# ------------------------------------------------------------ letra de drive (bug 'E::')

@VARIACOES
@given(letra=letras, antes=st.text(alphabet=" ", max_size=3), depois=separadores)
def test_qualquer_forma_de_digitar_a_letra_vira_X_dois_pontos(letra, antes, depois):
    """'e', 'E:', 'E:\\', 'e:/', ' E :\\: ' ... tudo precisa virar 'E:'."""
    assert full_scan.normalizar_letras([antes + letra + depois]) == {letra.upper() + ":"}


@VARIACOES
@given(lixo=st.text(alphabet=": \\/", max_size=6))
def test_entrada_so_com_separadores_nao_vira_drive(lixo):
    assert full_scan.normalizar_letras([lixo]) == set()


# ------------------------------------------------------------ lista de hashes

hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@VARIACOES
@given(h=hex64, maiusculo=st.booleans(), espacos=st.text(alphabet=" \t", max_size=3))
def test_hash_valido_e_aceito_de_qualquer_jeito(h, maiusculo, espacos):
    linha = espacos + (h.upper() if maiusculo else h) + espacos
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "h.txt"
        p.write_text(linha + "\n", encoding="utf-8")
        assert hash_scanner.carregar_lista_local(p) == {h}


@VARIACOES
@given(linha=st.text(max_size=80).filter(lambda s: "\n" not in s and "\r" not in s))
def test_lixo_nunca_entra_na_lista_de_hashes(linha):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "h.txt"
        p.write_text(linha + "\n", encoding="utf-8")
        for h in hash_scanner.carregar_lista_local(p):
            assert len(h) == 64 and set(h) <= set("0123456789abcdef")


# ------------------------------------------------------------ hosts (bug 'nextcloud' = banco)

rotulo = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=8)
marcas = st.sampled_from(["itau", "bradesco", "nubank", "paypal", "binance", "santander"])


@VARIACOES
@given(marca=marcas, prefixo=rotulo, sufixo=rotulo, ip=st.sampled_from(["192.168.0.10", "10.0.0.5", "203.0.113.9"]))
def test_marca_dentro_de_outra_palavra_nao_e_banco(marca, prefixo, sufixo, ip):
    """'meuitau2.lan' ou 'nubankfake' grudado em outra palavra nao e o dominio do banco."""
    with tempfile.TemporaryDirectory() as d:
        hosts = Path(d) / "hosts"
        hosts.write_text(f"{ip} {prefixo}{marca}{sufixo}.lan\n", encoding="utf-8")
        assert hosts_integrity.auditar(hosts) == []


@VARIACOES
@given(marca=marcas, sub=st.one_of(st.just(""), rotulo.map(lambda r: r + ".")),
       tld=st.sampled_from([".com", ".com.br"]))
def test_dominio_real_do_banco_redirecionado_e_pego(marca, sub, tld):
    with tempfile.TemporaryDirectory() as d:
        hosts = Path(d) / "hosts"
        hosts.write_text(f"203.0.113.9 {sub}{marca}{tld}\n", encoding="utf-8")
        assert [a.tipo for a in hosts_integrity.auditar(hosts)] == ["hijack_financeiro"]


# ------------------------------------------------------------ processos

nome_exe = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10).map(lambda s: s + ".exe")


@VARIACOES
@given(nome=nome_exe, pasta=st.sampled_from([
    r"C:\Program Files\App", r"C:\Program Files (x86)\Vendor\Bin", r"D:\Jogos\Steam",
]))
def test_programa_comum_em_pasta_normal_nao_gera_sinal(nome, pasta):
    if nome in process_scanner.NOMES_SISTEMA_IMPERSONADOS:
        return
    assert process_scanner.avaliar_processo(nome, f"{pasta}\\{nome}", "explorer.exe") == []


@VARIACOES
@given(nome=nome_exe, usuario=rotulo)
def test_qualquer_exe_rodando_do_temp_gera_sinal(nome, usuario):
    exe = f"C:\\Users\\{usuario}\\AppData\\Local\\Temp\\{nome}"
    assert process_scanner.avaliar_processo(nome, exe, "explorer.exe") != []


# ------------------------------------------------------------ quarentena

RESERVADOS_WINDOWS = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}


def _nome_valido(s: str) -> bool:
    # Nomes reservados do Windows (NUL, CON...) nem existem como arquivo -
    # o Hypothesis achou isso; e limite do sistema, nao bug do AV-Py.
    base = s.split(".")[0].strip().upper()
    return s.strip(" .") != "" and base not in RESERVADOS_WINDOWS and not s.endswith((" ", "."))


nome_arquivo = st.text(alphabet=string.ascii_letters + string.digits + " _-.()", min_size=1, max_size=20).filter(_nome_valido)


@VARIACOES
@given(nome=nome_arquivo, conteudo=st.binary(max_size=256))
def test_dry_run_nunca_toca_no_disco(nome, conteudo):
    with tempfile.TemporaryDirectory() as d:
        raiz = Path(d)
        alvo = raiz / nome
        alvo.write_bytes(conteudo)
        original_q, original_log = quarantine.PASTA_QUARENTENA, quarantine.LOG_QUARENTENA
        quarantine.PASTA_QUARENTENA = raiz / "quarantine"
        quarantine.LOG_QUARENTENA = raiz / "logs" / "q.log"
        try:
            quarantine.isolar(alvo, motivo="t", dry_run=True)
            assert alvo.read_bytes() == conteudo
            assert not (raiz / "quarantine").exists()
            assert not (raiz / "logs").exists()
        finally:
            quarantine.PASTA_QUARENTENA, quarantine.LOG_QUARENTENA = original_q, original_log


@VARIACOES
@given(nome=nome_arquivo, conteudo=st.binary(max_size=256))
def test_isolar_preserva_o_conteudo_byte_a_byte(nome, conteudo):
    with tempfile.TemporaryDirectory() as d:
        raiz = Path(d)
        alvo = raiz / nome
        alvo.write_bytes(conteudo)
        original_q, original_log = quarantine.PASTA_QUARENTENA, quarantine.LOG_QUARENTENA
        quarantine.PASTA_QUARENTENA = raiz / "quarantine"
        quarantine.LOG_QUARENTENA = raiz / "logs" / "q.log"
        try:
            destino = quarantine.isolar(alvo, motivo="t")
            assert destino.read_bytes() == conteudo
            assert quarantine.listar()[-1]["sha256"] == hashlib.sha256(conteudo).hexdigest()
        finally:
            quarantine.PASTA_QUARENTENA, quarantine.LOG_QUARENTENA = original_q, original_log

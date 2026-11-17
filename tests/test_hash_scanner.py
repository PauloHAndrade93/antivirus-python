import hashlib

from core import hash_scanner


def test_sha256_do_arquivo(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"av-py")
    assert hash_scanner.sha256_do_arquivo(p) == hashlib.sha256(b"av-py").hexdigest()


def test_lista_local_ignora_comentarios_e_lixo(tmp_path):
    bom = "a" * 64
    lista = tmp_path / "hashes.txt"
    lista.write_text(
        "# comentario\n"
        f"{bom.upper()}\n"          # maiusculas sao normalizadas
        "\n"
        "curto\n"
        + "z" * 64 + "\n",          # 64 caracteres, mas nao e hexadecimal
        encoding="utf-8",
    )
    assert hash_scanner.carregar_lista_local(lista) == {bom}


def test_lista_local_inexistente(tmp_path):
    assert hash_scanner.carregar_lista_local(tmp_path / "nao_existe.txt") == set()


def test_escanear_encontra_hash_listado(tmp_path):
    alvo = tmp_path / "sub" / "malicioso.txt"
    alvo.parent.mkdir()
    alvo.write_bytes(b"conteudo marcado")
    limpo = tmp_path / "limpo.txt"
    limpo.write_bytes(b"nada aqui")

    lista = {hashlib.sha256(b"conteudo marcado").hexdigest()}
    deteccoes = hash_scanner.escanear(tmp_path, lista)

    assert [d.arquivo for d in deteccoes] == [alvo]
    assert deteccoes[0].fonte == "lista_local"


def test_escanear_pula_pasta_de_quarentena(tmp_path):
    q = tmp_path / "quarantine"
    q.mkdir()
    (q / "isolado.quarantined").write_bytes(b"conteudo marcado")
    lista = {hashlib.sha256(b"conteudo marcado").hexdigest()}
    assert hash_scanner.escanear(tmp_path, lista) == []

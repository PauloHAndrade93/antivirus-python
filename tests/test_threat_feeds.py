from core import threat_feeds


class RespostaFalsa:
    def __init__(self, dados):
        self._dados = dados

    def raise_for_status(self):
        pass

    def json(self):
        return self._dados


def test_malwarebazaar_mescla_sem_duplicar(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSE_CH_API_KEY", "chave-de-teste")
    existente, novo = "a" * 64, "b" * 64
    destino = tmp_path / "hashes.txt"
    destino.write_text(f"# cabecalho\n{existente}\n", encoding="utf-8")

    def post_falso(url, **kwargs):
        assert kwargs["headers"]["Auth-Key"] == "chave-de-teste"
        return RespostaFalsa({"query_status": "ok", "data": [
            {"sha256_hash": novo}, {"sha256_hash": existente.upper()}, {"sha256_hash": "lixo"},
        ]})

    monkeypatch.setattr(threat_feeds.requests, "post", post_falso)
    adicionados, total = threat_feeds.atualizar_malwarebazaar(destino)

    assert (adicionados, total) == (1, 2)
    texto = destino.read_text(encoding="utf-8")
    assert texto.startswith("# cabecalho")
    assert texto.count(existente) == 1


def test_sem_chave_nao_chama_a_rede(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    monkeypatch.setattr(threat_feeds.requests, "post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("rede!")))
    try:
        threat_feeds.atualizar_malwarebazaar(tmp_path / "h.txt")
    except RuntimeError as e:
        assert "abuse.ch" in str(e)
    else:
        raise AssertionError("deveria exigir chave")


def test_dominios_de_urls(tmp_path):
    p = tmp_path / "urls.txt"
    p.write_text("# x\nhttp://Mal.Example/a\nhttps://mal.example/b\nhttp://outro.test/\n", encoding="utf-8")
    assert threat_feeds.dominios_urlhaus(p) == {"mal.example", "outro.test"}

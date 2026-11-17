"""
Heuristicas de comportamento: ransomware, hosts, processos e persistencia.
Cada caso aqui e uma "regra do jogo" escrita em codigo.
"""

import pytest

from core import hosts_integrity, persistence_checker, process_scanner, virustotal

ransom = pytest.importorskip("core.ransom_watcher")
pytest.importorskip("watchdog")


# ------------------------------------------------------------ ransomware

@pytest.fixture
def handler():
    alertas = []
    h = ransom._Handler(janela_segundos=10, limite_eventos=5, on_alerta=alertas.append)
    h.alertas = alertas
    return h


def test_cifragem_em_massa_dispara_uma_vez(handler):
    for _ in range(12):
        handler._marca_evento()
    tipos = [a.tipo for a in handler.alertas]
    assert tipos.count("massa") == 1  # debounce: nao inunda de alertas


@pytest.mark.parametrize("nome", ["contrato.docx.locked", "foto.jpg.WNCRY", "planilha.xlsx.ryk"])
def test_extensao_de_ransomware(handler, nome):
    handler._checa_extensao(nome)
    assert [a.tipo for a in handler.alertas] == ["extensao"]


@pytest.mark.parametrize("nome", ["Cargo.lock", "poetry.lock", "yarn.lock", "relatorio.docx"])
def test_arquivos_legitimos_nao_disparam_extensao(handler, nome):
    """Regressao: '.lock' e extensao comum de projetos de programacao."""
    handler._checa_extensao(nome)
    assert handler.alertas == []


@pytest.mark.parametrize("nome", ["HOW_TO_DECRYPT.txt", "README_RECOVERY.html", "your_files_are_encrypted.txt", "RANSOM_NOTE.txt"])
def test_nota_de_resgate(handler, nome):
    handler._checa_nota(nome)
    assert [a.tipo for a in handler.alertas] == ["nota"]


@pytest.mark.parametrize("nome", ["ransom_watcher.py", "README.md", "test_ransomware_detector.py"])
def test_arquivos_comuns_nao_sao_nota_de_resgate(handler, nome):
    """Regressao: o proprio codigo do AV-Py ('ransom_watcher.py') era marcado como nota."""
    handler._checa_nota(nome)
    assert handler.alertas == []


# ------------------------------------------------------------ hosts

def test_hosts_detecta_bloqueio_e_pharming(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost\n"
        "# 0.0.0.0 avast.com\n"
        "0.0.0.0 update.microsoft.com\n"
        "203.0.113.5 www.itau.com.br\n",
        encoding="utf-8",
    )
    tipos = sorted(a.tipo for a in hosts_integrity.auditar(hosts))
    assert tipos == ["bloqueio_security", "hijack_financeiro"]


@pytest.mark.parametrize("linha", [
    "192.168.0.10 nextcloud.lan",       # 'next' nao e o banco Next
    "10.0.0.5 intranet.empresa.local",  # 'inter' nao e o Banco Inter
    "0.0.0.0 preset.example.com",       # 'eset' dentro de outra palavra
    "0.0.0.0 ads.tracker.example",      # bloqueio de anuncio comum
])
def test_hosts_sem_falso_positivo(tmp_path, linha):
    hosts = tmp_path / "hosts"
    hosts.write_text(linha + "\n", encoding="utf-8")
    assert hosts_integrity.auditar(hosts) == []


def test_hosts_inexistente_vira_erro(tmp_path):
    assert hosts_integrity.auditar(tmp_path / "nao_existe")[0].tipo == "erro"


# ------------------------------------------------------------ processos

@pytest.mark.parametrize("nome,exe,pai,trecho", [
    ("evil.exe", r"C:\Users\x\AppData\Local\Temp\evil.exe", "explorer.exe", "Temp"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "winword.exe", "LOLBAS"),
    ("svchost.exe", r"C:\Users\x\svchost.exe", "explorer.exe", "impersonacao"),
    ("fatura.pdf.exe", r"D:\fatura.pdf.exe", "explorer.exe", "extensao dupla"),
])
def test_processo_suspeito(nome, exe, pai, trecho):
    sinais = process_scanner.avaliar_processo(nome, exe, pai)
    assert any(trecho in s for s in sinais), sinais


@pytest.mark.parametrize("nome,exe,pai", [
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "explorer.exe"),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "explorer.exe"),
])
def test_processo_legitimo(nome, exe, pai):
    assert process_scanner.avaliar_processo(nome, exe, pai) == []


# ------------------------------------------------------------ persistencia

def test_persistencia_legitima():
    assert persistence_checker._sinais_para(r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background') == []


def test_persistencia_powershell_oculto():
    sinais = persistence_checker._sinais_para("powershell -w hidden -EncodedCommand QUJD==")
    assert any("LOLBAS" in s for s in sinais)


def test_persistencia_em_pasta_temporaria():
    sinais = persistence_checker._sinais_para(r"C:\Users\x\AppData\Local\Temp\upd.exe")
    assert any("temporaria" in s for s in sinais)


# ------------------------------------------------------------ virustotal

@pytest.mark.parametrize("valor,tipo", [
    ("a" * 64, "hash"), ("a" * 40, "hash"), ("a" * 32, "hash"),
    ("8.8.8.8", "ip"), ("example.com", "dominio"),
    ("a" * 63, None), ("nada", None), ("", None),
])
def test_vt_detecta_tipo(valor, tipo):
    assert virustotal.detectar_tipo(valor) == tipo


def test_vt_sem_chave_nao_faz_requisicao():
    v = virustotal.consultar_auto("8.8.8.8", api_key="")
    assert v.nivel == "erro"

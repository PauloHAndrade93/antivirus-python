import pytest

from core import full_scan
from core.full_scan import Drive

DRIVES = [
    Drive(letra="C:\\", tipo="fixed", fstype="NTFS"),
    Drive(letra="E:\\", tipo="removable", fstype="FAT32"),
    Drive(letra="Z:\\", tipo="network", fstype=""),
]


@pytest.mark.parametrize("entrada", ["E", "e", "E:", "e:", "E:\\", " E: ", "E::"])
def test_normaliza_letra_de_drive(entrada):
    """Regressao: o av-py.bat mandava 'E::' e nenhum drive era selecionado."""
    assert full_scan.normalizar_letras([entrada]) == {"E:"}


def test_normaliza_ignora_vazio():
    assert full_scan.normalizar_letras(["", "  "]) == set()


def test_filtra_por_letra():
    sel = full_scan.filtrar_drives(DRIVES, somente_letras={"E:"})
    assert [d.letra for d in sel] == ["E:\\"]


def test_filtra_somente_usb():
    sel = full_scan.filtrar_drives(DRIVES, apenas_usb=True)
    assert [d.tipo for d in sel] == ["removable"]


def test_por_padrao_pula_drive_de_rede():
    sel = full_scan.filtrar_drives(DRIVES)
    assert "network" not in {d.tipo for d in sel}


def test_exclusoes_de_sistema(tmp_path):
    raiz = tmp_path
    assert full_scan._deve_pular_pasta(raiz / "Windows" / "WinSxS", raiz)
    assert full_scan._deve_pular_pasta(raiz / "$Recycle.Bin", raiz)
    assert not full_scan._deve_pular_pasta(raiz / "Users" / "paulo" / "Downloads", raiz)


def test_remove_duplicados_por_arquivo(tmp_path):
    """Um arquivo que casa com 2 regras nao pode ser isolado 2 vezes."""
    a = tmp_path / "a.exe"
    dets = [
        full_scan.DeteccaoCompleta(arquivo=a, motor="yara", detalhe="regra 1"),
        full_scan.DeteccaoCompleta(arquivo=a, motor="yara", detalhe="regra 2"),
        full_scan.DeteccaoCompleta(arquivo=tmp_path / "b.exe", motor="hash", detalhe="x"),
    ]
    unicos = full_scan.unicos_por_arquivo(dets)
    assert [d.arquivo.name for d in unicos] == ["a.exe", "b.exe"]

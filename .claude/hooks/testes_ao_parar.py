"""
Hook "Stop" do Claude Code: o agente nao encerra o trabalho com teste vermelho.

Fluxo (o mesmo do podcast: o agente executa, ve o erro, corrige, repete):
  1. Se nao ha mudanca nao commitada em codigo/regras/testes, nao faz nada.
  2. Roda a suite (com menos variacoes do Hypothesis, para ser rapido).
  3. Tudo verde -> deixa parar.
  4. Algo vermelho -> sai com codigo 2 e manda o resumo da falha para o
     agente, que continua trabalhando seguindo a skill 'corrigir-bug'.
  5. Depois de 3 tentativas seguidas sem sucesso, deixa parar e avisa a
     pessoa (evita loop infinito).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
CONTADOR = Path(__file__).with_name(".tentativas")
MAX_TENTATIVAS = 3
EXTENSOES = (".py", ".yar", ".yara", ".ini", ".txt", ".html", ".js", ".css")


def _ha_mudancas_relevantes() -> bool:
    try:
        saida = subprocess.run(
            ["git", "status", "--porcelain"], cwd=RAIZ,
            capture_output=True, text=True, timeout=20,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return True  # na duvida, testa
    for linha in saida.splitlines():
        caminho = linha[3:].strip().strip('"')
        if caminho.endswith(EXTENSOES) or caminho.endswith("/"):
            return True
    return False


def _ler_tentativas() -> int:
    try:
        return int(CONTADOR.read_text().strip())
    except (OSError, ValueError):
        return 0


def main() -> int:
    try:
        json.loads(sys.stdin.read() or "{}")
    except ValueError:
        pass

    if not _ha_mudancas_relevantes():
        CONTADOR.unlink(missing_ok=True)
        return 0

    env = {**os.environ, "AVPY_VARIACOES": "60", "PYTHONIOENCODING": "utf-8"}
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-x", "-q", "--tb=short", "-p", "no:cacheprovider"],
        cwd=RAIZ, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )

    if res.returncode == 0:
        CONTADOR.unlink(missing_ok=True)
        return 0

    tentativas = _ler_tentativas() + 1
    if tentativas > MAX_TENTATIVAS:
        CONTADOR.unlink(missing_ok=True)
        print(json.dumps({
            "systemMessage": f"AV-Py: os testes continuam falhando depois de {MAX_TENTATIVAS} "
                             "tentativas automaticas. Revise antes de commitar.",
        }))
        return 0

    CONTADOR.write_text(str(tentativas))
    resumo = (res.stdout + res.stderr)[-3500:]
    sys.stderr.write(
        f"[AV-Py] Testes falhando (tentativa {tentativas}/{MAX_TENTATIVAS}). "
        "Nao encerre ainda: siga a skill 'corrigir-bug' (.claude/skills/corrigir-bug/SKILL.md) - "
        "corrija a causa, gere variacoes do mesmo erro como testes e rode a suite de novo.\n\n"
        + resumo
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())

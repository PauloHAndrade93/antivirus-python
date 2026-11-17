# AGENTS.md — regras para quem (pessoa ou agente de IA) mexe no AV-Py

Este arquivo é lido automaticamente por harnesses compatíveis (Claude Code, Codex, Antigravity, OpenCode…). Ele é a fonte única das regras do projeto.

## O que é o projeto

AV-Py é um antivírus / EDR leve **defensivo**, em Python, para estudo. Ele detecta, audita e isola. Ele **não** ataca.

## Limites que não se negociam

- **Só defesa.** Nada de código ofensivo: sem exploits, sem malware funcional, sem "melhorar" amostras, sem evasão de antivírus. Amostras de teste são strings montadas em memória (veja `tests/test_regras_yara.py`).
- **Painel só local.** `web/app.py` escuta em `127.0.0.1`, exige token, confere `Host` e valida parâmetros por lista branca. Nenhuma mudança pode afrouxar isso.
- **Segredos só em variável de ambiente** (`VT_API_KEY`, `ABUSE_CH_API_KEY`). Nunca commitar, nunca imprimir o valor, nunca mandar ao navegador.

## Como trabalhar

1. **Diga o que quer e o que NÃO quer.** Toda tarefa começa com o objetivo e com o que não pode mudar (ex.: "reduzir falso positivo na regra X *sem* perder os casos positivos que já existem").
2. **Todo bug corrigido ganha um teste de regressão** em `tests/`, que falha sem a correção e passa com ela. O nome do teste ou o docstring diz qual bug ele protege.
3. **Toda mudança em regra YARA vem com caso positivo E negativo** em `tests/test_regras_yara.py`. Lembrete: o YARA ignora em silêncio repetições acima de `{1024}` em regex — por isso a regra precisa de teste positivo, não basta compilar.
4. **Heurística nova = função pura testável.** Separe a decisão (ex.: `process_scanner.avaliar_processo`) da coleta de dados do sistema.
5. **Operação destrutiva tem simulação e conferência.** Quarentena tem `--dry-run` e confere o SHA-256 antes e depois de mover. Qualquer nova ação que mova/apague arquivos segue o mesmo padrão.
6. **Rode os testes antes de commitar:** `python -m pytest -q`. O CI (GitHub Actions) roda a mesma suíte em Windows e Linux a cada push; ele precisa ficar verde.
7. **Commits sem linha de coautoria de IA** (preferência do autor do projeto).

## Comandos

```bash
pip install -r requirements-dev.txt     # dependências + pytest
python -m pytest -q                     # suíte completa (~1 s)
python av.py --help                     # CLI
python web/app.py                       # painel em http://127.0.0.1:8765
```

## Mapa rápido

| Pasta | Conteúdo |
|-------|----------|
| `core/` | um módulo por técnica de detecção |
| `rules/` | regras YARA e listas de IoCs |
| `web/` | painel local (Flask) |
| `tests/` | regras do projeto escritas como teste |

---
name: corrigir-bug
description: Corrige um bug do AV-Py do jeito certo - reproduz com teste que falha, corrige, gera N variacoes de como o mesmo erro pode voltar e vacina o codigo contra todas. Use sempre que aparecer um erro, falso positivo, falso negativo, traceback ou comportamento inesperado no AV-Py.
---

# Corrigir bug e vacinar contra variações

Objetivo: o bug que apareceu **e as formas parecidas dele** nunca mais voltam.
O que NÃO pode acontecer: afrouxar um teste para ele passar, perder detecção que já existia, ou mexer em código ofensivo.

## 1. Reproduzir antes de corrigir

1. Leia o erro (traceback, saída da CLI ou relato do usuário).
2. Escreva um teste em `tests/` que reproduz o problema exatamente como aconteceu.
3. Rode `python -m pytest -q tests/<arquivo>.py` e **confirme que ele falha**. Se não falhar, você não reproduziu o bug: volte ao passo 1.

## 2. Corrigir a causa, não o sintoma

- Conserte o código em `core/`, `web/` ou `rules/`. **Nunca** mude o teste para aceitar o comportamento errado.
- Se a lógica está misturada com acesso ao sistema (psutil, registro, disco), extraia a decisão para uma função pura e teste essa função.

## 3. Gerar N variações do mesmo erro

Pergunte: "de que outras formas esse mesmo erro aparece?". Para cada eixo abaixo que se aplica, crie casos:

| Eixo | Exemplos |
|------|----------|
| Maiúscula/minúscula | `E:` / `e:`; `HOW_TO_DECRYPT` / `how_to_decrypt` |
| Separadores e espaços | `\`, `/`, `:`, espaço antes/depois, repetidos (`E::`) |
| Vazio e só lixo | `""`, `"   "`, `"/"`, só pontuação |
| Limites | um a menos / exato / um a mais (ex.: base64 com 999, 1000, 1001 caracteres) |
| Substring enganosa | marca dentro de outra palavra (`nextcloud`, `preset`, `ransom_watcher.py`) |
| Plataforma | caminhos Windows e Linux; nomes reservados (`NUL`, `CON`) |
| Unicode / acentos | `Configurações`, `Vídeos`, emoji em nome de arquivo |
| Tamanho | arquivo vazio, muito grande, linha gigante |
| Ordem e repetição | mesmo arquivo detectado duas vezes, mesma regra duas vezes |

- Casos pontuais → `@pytest.mark.parametrize` no arquivo do módulo.
- Propriedades gerais ("qualquer X deve dar Y") → teste com Hypothesis em `tests/test_variacoes.py`, com `@settings(max_examples=300)`.
- Para regra YARA: sempre **um caso positivo e um negativo** em `tests/test_regras_yara.py`, montando as strings em memória (por concatenação), nunca como arquivo malicioso no repositório.

## 4. Provar que está vacinado

1. `python -m pytest` → tudo verde (a suíte inteira, não só o arquivo novo).
2. Se o Hypothesis achar um novo contraexemplo, ele é um bug novo: volte ao passo 2 com ele.
3. Se a variação for limite do sistema operacional e não do AV-Py (ex.: arquivo `NUL`), filtre no gerador e explique em comentário.

## 5. Registrar

- Adicione uma linha na tabela "Bugs que os testes já pegaram" do `README.md`.
- Commit sem linha de coautoria de IA, explicando: bug, causa, correção e variações cobertas.

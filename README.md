# 🛡️ AV-Py — Antivírus defensivo em Python

> Projeto pessoal de cibersegurança: um **EDR leve** (Endpoint Detection and Response) escrito em Python, para estudo e proteção complementar ao antivírus do sistema.

Não substitui o Microsoft Defender (nem deveria). É uma **camada extra** de verificação e monitoramento, pensada para quem está aprendendo segurança e quer entender, na prática, como as ferramentas profissionais funcionam.

---

## 🎯 O que o AV-Py faz

Seis módulos, trabalhando juntos:

| Módulo | O que faz | Técnica profissional por trás |
|--------|-----------|------------------------------|
| **Hash Scanner** | Calcula o SHA-256 de cada arquivo e consulta a base pública do [MalwareBazaar](https://bazaar.abuse.ch/) | *IoC matching* por hash — o modo mais rápido de pegar malware conhecido |
| **YARA Scanner** | Varre arquivos com regras [YARA](https://virustotal.github.io/yara/), a linguagem padrão de *threat hunting* | *Pattern matching* por família de malware, usado pela indústria toda |
| **Network Monitor** | Vigia conexões de saída suspeitas (portas de C2, SMTP de processos não-correio, beaconing) | Detecção de **exfiltração** e **command & control** |
| **Ransom Watcher** | Observa pastas sensíveis em tempo real e grita contra cifragem em massa, extensões típicas (`.locked`, `.wncry`…) e notas de resgate | Detecção comportamental de **ransomware** (T1486 / T1490) |
| **Persistence Checker** | Audita Run keys do registro, pastas Startup, tarefas agendadas e serviços de auto-início | Detecção de **persistência** (T1547.001, T1053.005, T1543.003) |
| **VirusTotal Lookup** 🆕 | Consulta reputação de hash, IP e domínio no VirusTotal (70+ engines consolidados) | *Reputation lookup* como segunda opinião |

Cada detecção do scan pode gerar **quarentena automática** do arquivo (move para pasta isolada e registra em log).

---

## 📦 Estrutura

```
antivirus-python/
├── av.py                       # CLI principal
├── requirements.txt
├── core/
│   ├── hash_scanner.py         # SHA-256 + MalwareBazaar
│   ├── yara_scanner.py         # Engine YARA
│   ├── network_monitor.py      # Monitor de conexões
│   ├── ransom_watcher.py       # Heurística anti-ransomware (watchdog)
│   ├── persistence_checker.py  # Auditoria de persistência no Windows
│   ├── virustotal.py           # Cliente da API v3 do VirusTotal
│   └── quarantine.py           # Isolamento de arquivos suspeitos
├── rules/
│   └── exemplo.yar             # Regras YARA (comece por aqui)
├── quarantine/                 # Arquivos isolados (gerado em runtime)
└── logs/                       # Logs de deteção (gerado em runtime)
```

---

## 🚀 Como usar

### 1. Instalar dependências

```bash
pip install -r requirements.txt
```

> No Windows, o pacote `yara-python` instala direto via wheel. Se der erro, instale o [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

### 2. (Opcional) Configurar chave do MalwareBazaar

O MalwareBazaar exige uma chave de API gratuita. Cadastre em https://bazaar.abuse.ch/account/ e depois:

```bash
# Windows PowerShell
$env:MALWAREBAZAAR_API_KEY="sua_chave_aqui"
```

Sem a chave, o scanner de hash funciona em **modo offline**: só compara contra a lista local em `rules/hashes_locais.txt` (um hash por linha).

### 3. Rodar

**Opção fácil (Windows):** duplo-clique em **`av-py.bat`** — abre um menu com todas as ações.

**Opção manual:**

```bash
# Scan de uma pasta
python av.py scan "C:\Users\paulo\Downloads"

# Scan com quarentena automática
python av.py scan "C:\Users\paulo\Downloads" --quarantine

# Monitor de rede (contínuo, Ctrl+C para parar)
python av.py netmon

# Vigia pastas sensíveis contra ransomware (Ctrl+C para parar)
python av.py watch "C:\Users\paulo\Documents" "C:\Users\paulo\Desktop"

# Audita persistência (só itens suspeitos)
python av.py persist

# Audita persistência mostrando tudo (inventário completo)
python av.py persist --all

# Consulta VirusTotal (hash, IP ou domínio — autodetecta o tipo)
python av.py vt 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
python av.py vt 8.8.8.8 badsite.example.com

# Scan + segunda opinião no VirusTotal para hashes não-casados
python av.py scan "C:\Users\paulo\Downloads" --vt

# Ver tudo que está em quarentena
python av.py quarantine --list
```

### 🔬 Como funciona o VirusTotal Lookup

O [VirusTotal](https://www.virustotal.com/) roda cada amostra em **70+ antivírus** e publica o veredito consolidado. O AV-Py usa isso como *segunda opinião*:

1. **Cadastre uma chave gratuita** em https://www.virustotal.com/gui/my-apikey
2. Exporte na variável de ambiente `VT_API_KEY`
3. Use `python av.py vt <alvo>` pra consulta pontual, ou `scan --vt` para integrar ao scan

Níveis emitidos: `malicioso` (≥5 engines), `suspeito` (1–4 engines ou suspicious≥3), `limpo`, `desconhecido` ou `erro`.

**Limite da conta gratuita:** 4 req/min e 500/dia. O cliente respeita o limite automaticamente.

### 🔎 Como funciona o modo `persist` (verificador de persistência)

Malware precisa sobreviver ao reboot. Só existem alguns lugares onde isso cabe no Windows, e o `persist` olha todos eles:

| Local | Técnica MITRE |
|-------|---------------|
| Chaves `Run` / `RunOnce` do Registro (HKLM e HKCU) | T1547.001 |
| Pastas `Startup` do usuário e de todos os usuários | T1547.001 |
| Tarefas agendadas (fora de `\Microsoft\`) | T1053.005 |
| Serviços com `Start = Auto` fora do padrão | T1543.003 |

Para cada entrada ele aplica heurísticas e sinaliza quando bate em:
- Caminho em `AppData\Local\Temp`, `Downloads`, `Users\Public` ou lixeira
- Comando com `powershell -EncodedCommand`, `-w hidden`, `mshta http`, `certutil -urlcache`, `bitsadmin /transfer`, `IEX`, `Invoke-Expression`
- Muita aspa (ofuscação) ou base64 embutido

Sem `--all`, ele mostra **só o que levantou sinal**. Ele não remove nada — a decisão é sua.

### 🛡️ Como funciona o modo `watch` (anti-ransomware)

Enquanto ele roda, três gatilhos disparam alertas, independentes:

1. **Massa** — muitos eventos de arquivo em janela curta (padrão: 30 em 10s). Ransomware cifra rápido.
2. **Extensão** — qualquer arquivo nascendo com extensão típica (`.locked`, `.wncry`, `.ryk`, `.encrypted`...).
3. **Nota de resgate** — arquivos criados com nomes como `HOW_TO_DECRYPT.txt`, `README_RECOVERY.html`.

Ajuste a sensibilidade com `--janela` e `--limite`. Os alertas também vão para `logs/ransom.log` (um JSONL por linha) pra análise posterior.

---

## 🧪 Como testar com segurança

**Nunca** baixe malware de verdade pra testar. Use estes jeitos seguros:

1. **EICAR** — arquivo de teste oficial, inofensivo, que todo AV reconhece:
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
   Salve isso em um `.txt` e passe o scanner.

2. **Amostras benignas** — crie arquivos `.py` ou `.exe` falsos que casem com as regras YARA de exemplo.

3. **Hashes públicos de IoCs** — pegue hashes da própria MalwareBazaar e coloque em arquivos fake de nome igual, pra testar o fluxo.

---

## 🧭 Roadmap

- [x] Watcher de arquivos com `watchdog` (anti-ransomware heurístico)
- [x] Verificador de persistência (Run keys, Startup, Scheduled Tasks, Serviços)
- [x] Reputation lookup via VirusTotal API (hash, IP, domínio + integração no scan)
- [ ] Dashboard web local (Flask) com histórico de alertas
- [ ] Integração com MITRE ATT&CK — classificar cada detecção por técnica

---

## ⚠️ Avisos

- Rode apenas no **seu próprio computador** ou em uma **VM de laboratório**.
- Isto é um **projeto de estudo**. Para proteção real, mantenha o Defender (ou outro AV comercial) ativo em paralelo.
- A quarentena **move** o arquivo. Reveja a pasta `quarantine/` antes de apagar qualquer coisa.

---

## 📚 Referências

- [YARA — The pattern matching swiss knife](https://virustotal.github.io/yara/)
- [MalwareBazaar — abuse.ch](https://bazaar.abuse.ch/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [EICAR test file](https://www.eicar.org/)

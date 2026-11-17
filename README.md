# 🛡️ AV-Py — Antivírus defensivo em Python

> Projeto pessoal de cibersegurança: um **EDR leve** (Endpoint Detection and Response) escrito em Python, para estudo e proteção complementar ao antivírus do sistema.

Não substitui o Microsoft Defender (nem deveria). É uma **camada extra** de verificação e monitoramento, pensada para quem está aprendendo segurança e quer entender, na prática, como as ferramentas profissionais funcionam.

---

## 🎯 O que o AV-Py faz

Onze módulos, trabalhando juntos:

| Módulo | O que faz | Técnica profissional por trás |
|--------|-----------|------------------------------|
| **Hash Scanner** | Calcula o SHA-256 de cada arquivo e consulta a base pública do [MalwareBazaar](https://bazaar.abuse.ch/) | *IoC matching* por hash — o modo mais rápido de pegar malware conhecido |
| **YARA Scanner** | Varre arquivos com regras [YARA](https://virustotal.github.io/yara/), a linguagem padrão de *threat hunting* | *Pattern matching* por família de malware, usado pela indústria toda |
| **Full Scan** | Varre **drives inteiros** — HD, SSD, pendrive, cartão SD — com progresso em tempo real e exclusões inteligentes | *Full endpoint sweep*, como um AV comercial faz no "Verificação completa" |
| **Signature Check** 🆕 | Verifica assinatura Authenticode. Executáveis assinados por publishers confiáveis (Microsoft, Google, Mozilla, Steam…) têm match YARA ignorado automaticamente | *Trust anchoring* via certificado — elimina 90% dos falsos positivos em `.exe` |
| **Network Monitor** | Vigia conexões de saída suspeitas (portas de C2, SMTP de processos não-correio, beaconing) | Detecção de **exfiltração** e **command & control** |
| **Ransom Watcher** | Observa pastas sensíveis em tempo real e grita contra cifragem em massa, extensões típicas (`.locked`, `.wncry`…) e notas de resgate | Detecção comportamental de **ransomware** (T1486 / T1490) |
| **Persistence Checker** | Audita Run keys do registro, pastas Startup, tarefas agendadas e serviços de auto-início | Detecção de **persistência** (T1547.001, T1053.005, T1543.003) |
| **Process Scanner** 🆕 | Audita processos em execução: pastas suspeitas, cadeia pai-filho (Office → PowerShell), impersonação de serviço do Windows, extensão dupla | Detecção de malware **em memória** (T1055, T1059) |
| **Hosts Integrity** 🆕 | Verifica se o arquivo `hosts` foi alterado pra bloquear antivírus/updates ou redirecionar bancos/cripto (pharming) | *Integrity check* clássico (T1565.002) |
| **VirusTotal Lookup** | Consulta reputação de hash, IP e domínio no VirusTotal (70+ engines consolidados) | *Reputation lookup* como segunda opinião |
| **Threat Feeds** 🆕 | Baixa automaticamente hashes recentes do MalwareBazaar e URLs do URLHaus para engrossar a base local | *Threat intelligence feed ingestion* |

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
│   ├── process_scanner.py      # Auditoria de processos em execução (LOLBAS, LOT)
│   ├── hosts_integrity.py      # Integridade do arquivo hosts
│   ├── signature_check.py      # Whitelist por Authenticode (Microsoft, Google…)
│   ├── threat_feeds.py         # Ingestão de feeds MalwareBazaar + URLHaus
│   ├── virustotal.py           # Cliente da API v3 do VirusTotal
│   ├── full_scan.py            # Varredura completa de drives (HD/SSD/USB)
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

**Opção mais bonita:** duplo-clique em **`painel.bat`** — abre o painel web no navegador (veja abaixo).

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

# FULL SCAN — todos os drives (HD + SSD + pendrives) com progresso
python av.py fullscan

# Só pendrives e HDs externos
python av.py fullscan --usb-only

# Só o drive E:
python av.py fullscan --drive E:

# Full scan isolando o que achar
python av.py fullscan --quarantine

# Scan + segunda opinião no VirusTotal para hashes não-casados
python av.py scan "C:\Users\paulo\Downloads" --vt

# Audita processos em execução (LOLBAS, pastas suspeitas, impersonação)
python av.py procs

# Verifica integridade do arquivo hosts
python av.py hosts

# Atualiza bases locais com feeds da abuse.ch (precisa chave ABUSE_CH_API_KEY)
python av.py feeds-update

# Ver tudo que está em quarentena
python av.py quarantine --list
```

### 🖥️ Painel web local

`painel.bat` (ou `python web/app.py`) sobe um painel em **http://127.0.0.1:8765** e abre o navegador:

- **Painel** — status da proteção, contadores (hashes, regras YARA, URLs, quarentena), drives detectados e histórico da sessão
- **Varreduras, Monitoramento, Auditoria, Inteligência** — todas as ações do AV-Py em formulários
- **Console ao vivo** — a saída de cada tarefa aparece em tempo real, colorida, com métricas de progresso e botão de parar
- **Quarentena e Relatórios** — lista de arquivos isolados e leitor dos logs

Cuidados de segurança do próprio painel: escuta **só em 127.0.0.1**, exige um **token aleatório por execução** em toda ação (anti-CSRF), confere o cabecalho `Host` (anti DNS rebinding), valida cada parâmetro por lista branca, nunca usa shell e envia CSP restritiva. As chaves de API **nunca** chegam ao navegador — o painel só mostra se estão configuradas.

### ✅ Como funciona o Signature Check (whitelist)

O Full Scan só chama o `Get-AuthenticodeSignature` do PowerShell **depois** que o YARA bate em um executável. Se a assinatura é válida e o *publisher* está na lista de confiança (Microsoft, Google, Mozilla, Steam, Docker, Valve, GitHub, Python, JetBrains, NVIDIA, AMD, Intel, Realtek, Adobe, Apple, Oracle, Zoom, WhatsApp, Spotify, 7-Zip, VideoLAN…), a detecção é **ignorada** silenciosamente.

Na prática: a maioria dos falsos positivos em `.exe` do sistema some automaticamente.

### 🧬 Como funciona o Threat Feeds

Os feeds da abuse.ch (MalwareBazaar + URLHaus) são gratuitos mas desde 2024 **exigem uma chave de autenticação**. Cadastre uma em **https://auth.abuse.ch/** (é gratuita e serve para todos os serviços da abuse.ch) e exporte:

```bash
setx ABUSE_CH_API_KEY "sua_chave"
```

Depois, rode `python av.py feeds-update` quando quiser atualizar. Costumo recomendar **1 vez por semana** — o MalwareBazaar recebe centenas de amostras novas por dia.

Os hashes vão parar em `rules/hashes_locais.txt` (o mesmo arquivo que o Hash Scanner lê). As URLs vão para `rules/urls_maliciosas.txt` (uso futuro).

### 💽 Como funciona o Full Scan

O `fullscan` escaneia **drives inteiros** — HDs, SSDs, pendrives, cartões SD. Ele:

1. **Enumera todos os drives** montados e identifica o tipo (fixo, removível, CD, rede).
2. **Aplica filtros** (`--usb-only`, `--drive E:`), pulando por padrão drives de rede e CDs.
3. **Pula pastas caras e irrelevantes** como `Windows\WinSxS`, `$Recycle.Bin`, `System Volume Information`, `Program Files\WindowsApps`, `node_modules`, `.git`, caches de browser e a própria `quarantine/` (pra não reescanear).
4. **Pula arquivos especiais** como `pagefile.sys` e `hiberfil.sys`.
5. Para cada arquivo, roda **hash** (SHA-256 + lista local + opcional MalwareBazaar com `--use-mb`) e **YARA**.
6. **Mostra progresso** a cada 500 arquivos (configurável com `--progresso`).
7. **Trata sem crashear** permissão negada, arquivo em uso, etc.
8. No final, **grava relatório** completo em `logs/fullscan_<timestamp>.log`.

⏱️ **Duração típica:** um drive de 500 GB com uns 200k arquivos leva algo entre **20 minutos e 1 hora**, dependendo do SSD/HD. Um pendrive de 32 GB sai em poucos minutos.

🔐 **Não precisa de admin.** Arquivos protegidos por ACL simplesmente aparecem como "erro" no contador e são pulados.

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
- [x] Full Scan (drives inteiros, HD/SSD/USB/SD)
- [x] Signature Check (whitelist por Authenticode)
- [x] Process Scanner (LOLBAS, impersonação, extensão dupla)
- [x] Hosts Integrity (bloqueio AV / pharming)
- [x] Threat Feeds (MalwareBazaar + URLHaus auto-update)
- [x] Painel web local (Flask) com console ao vivo, quarentena e relatórios
- [ ] Watcher automático de USB (auto-scan ao inserir)
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

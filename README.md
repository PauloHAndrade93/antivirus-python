# 🛡️ AV-Py — Antivírus defensivo em Python

> Projeto pessoal de cibersegurança: um **EDR leve** (Endpoint Detection and Response) escrito em Python, para estudo e proteção complementar ao antivírus do sistema.

Não substitui o Microsoft Defender (nem deveria). É uma **camada extra** de verificação e monitoramento, pensada para quem está aprendendo segurança e quer entender, na prática, como as ferramentas profissionais funcionam.

---

## 🎯 O que o MVP faz

Três módulos, trabalhando juntos:

| Módulo | O que faz | Técnica profissional por trás |
|--------|-----------|------------------------------|
| **Hash Scanner** | Calcula o SHA-256 de cada arquivo e consulta a base pública do [MalwareBazaar](https://bazaar.abuse.ch/) | *IoC matching* por hash — o modo mais rápido de pegar malware conhecido |
| **YARA Scanner** | Varre arquivos com regras [YARA](https://virustotal.github.io/yara/), a linguagem padrão de *threat hunting* | *Pattern matching* por família de malware, usado pela indústria toda |
| **Network Monitor** | Vigia conexões de saída suspeitas (portas de C2, SMTP de processos não-correio, beaconing) | Detecção de **exfiltração** e **command & control** |

Cada detecção pode gerar **quarentena automática** do arquivo (move para pasta isolada e registra em log).

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

```bash
# Scan de uma pasta
python av.py scan "C:\Users\paulo\Downloads"

# Scan com quarentena automática
python av.py scan "C:\Users\paulo\Downloads" --quarantine

# Monitor de rede (contínuo, Ctrl+C para parar)
python av.py netmon

# Ver tudo que está em quarentena
python av.py quarantine --list
```

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

## 🧭 Roadmap depois do MVP

- [ ] Watcher de arquivos com `watchdog` (anti-ransomware heurístico: cifragem em massa)
- [ ] Verificador de persistência (Run keys, Startup, Scheduled Tasks)
- [ ] Reputation lookup via VirusTotal API
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

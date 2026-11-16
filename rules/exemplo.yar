/*
    Regras YARA de exemplo - AV-Py
    -----------------------------------------------------------
    Sao HEURISTICAS de estudo: ajudam a aprender sintaxe e podem
    gerar falsos positivos. Em producao, use conjuntos maduros como:
      - https://github.com/Yara-Rules/rules
      - https://github.com/Neo23x0/signature-base
*/

rule EICAR_Teste
{
    meta:
        descricao = "String oficial de teste EICAR - inofensiva"
        referencia = "https://www.eicar.org/"
        autor      = "AV-Py"
        severidade = "info"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}


rule Powershell_Suspeito_Download_Execucao
{
    meta:
        descricao = "Padroes classicos de dropper Powershell (download + execucao in-memory)"
        mitre      = "T1059.001 PowerShell; T1105 Ingress Tool Transfer"
        severidade = "alta"

    strings:
        $iex        = "IEX" nocase
        $invoke     = "Invoke-Expression" nocase
        $webclient  = "Net.WebClient" nocase
        $downstr    = "DownloadString" nocase
        $hidden     = "-w hidden" nocase
        $enc        = "-EncodedCommand" nocase

    condition:
        2 of them
}


rule Python_Keylogger_Heuristica
{
    meta:
        descricao = "Imports tipicos de keylogger em Python (pynput + SMTP)"
        mitre      = "T1056.001 Keylogging; T1048 Exfiltration over C2"
        severidade = "alta"

    strings:
        $pynput1 = "from pynput"
        $pynput2 = "pynput.keyboard"
        $smtp1   = "smtplib"
        $smtp2   = "smtp.gmail.com"
        $listener= "Listener(on_press"

    condition:
        ($pynput1 or $pynput2) and (any of ($smtp*)) and $listener
}


rule Macro_Office_Shell_Suspeito
{
    meta:
        descricao = "Macro de Office chamando shell / powershell (dropper tipico)"
        mitre      = "T1204.002 Malicious File; T1059 Command and Scripting"
        severidade = "alta"

    strings:
        $autoopen1 = "AutoOpen" nocase
        $autoopen2 = "Document_Open" nocase
        $shell1    = "Shell(" nocase
        $shell2    = "WScript.Shell" nocase
        $ps        = "powershell" nocase

    condition:
        (any of ($autoopen*)) and (any of ($shell*)) and $ps
}


rule Script_Base64_Grande
{
    meta:
        descricao = "Bloco Base64 muito grande - comum em droppers ofuscados"
        mitre      = "T1027 Obfuscated Files or Information"
        severidade = "media"

    strings:
        // 400+ chars base64 seguidos
        $b64 = /[A-Za-z0-9+\/]{400,}={0,2}/

    condition:
        $b64
}

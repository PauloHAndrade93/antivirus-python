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
        // Download + execucao in-memory (ambos sao necessarios)
        $down1 = "DownloadString" nocase
        $down2 = "DownloadData" nocase
        $down3 = "Net.WebClient" nocase
        $down4 = "Invoke-WebRequest" nocase
        $down5 = "Invoke-RestMethod" nocase

        $exec1 = "IEX" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "-EncodedCommand" nocase
        $exec4 = "FromBase64String" nocase

        // Ofuscacao / stealth que confirma intent malicioso
        $stealth1 = "-w hidden" nocase
        $stealth2 = "-WindowStyle Hidden" nocase
        $stealth3 = "-NoProfile -ExecutionPolicy Bypass" nocase
        $stealth4 = "-nop -ep bypass" nocase

    condition:
        (any of ($down*) and any of ($exec*))
        or (any of ($stealth*) and any of ($exec*))
}


rule Python_Keylogger_Heuristica
{
    meta:
        descricao = "Imports tipicos de keylogger em Python (pynput + SMTP + Listener)"
        mitre      = "T1056.001 Keylogging; T1048 Exfiltration over C2"
        severidade = "alta"

    strings:
        $pynput1 = "from pynput"
        $pynput2 = "pynput.keyboard"
        $smtp1   = "smtplib"
        $smtp2   = "smtp.gmail.com"
        $listener= "Listener(on_press"
        $send1   = "sendmail"
        $send2   = "starttls" nocase

    condition:
        ($pynput1 or $pynput2) and any of ($smtp*) and $listener and any of ($send*)
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


rule Script_Base64_Suspeito
{
    meta:
        descricao = "Base64 grande acompanhado de execucao/download (dropper ofuscado)"
        mitre      = "T1027 Obfuscated Files or Information"
        severidade = "media"

    strings:
        // 1500+ chars base64 em uma linha (certificados PEM tem quebras)
        $b64 = /[A-Za-z0-9+\/]{1500,}={0,2}/

        // Contexto de execucao/download que valida o dropper
        $exec1 = "FromBase64String" nocase
        $exec2 = "frombase64" nocase
        $exec3 = "IEX" nocase
        $exec4 = "Invoke-Expression" nocase
        $exec5 = "DownloadString" nocase
        $exec6 = "DownloadData" nocase
        $exec7 = "eval(" nocase
        $exec8 = "WScript.Shell" nocase
        $exec9 = "powershell -" nocase
        $exec10 = "cmd /c" nocase

        // Sinais que indicam certificado legitimo - excluem
        $cert1 = "-----BEGIN CERTIFICATE-----"
        $cert2 = "-----BEGIN PUBLIC KEY-----"
        $cert3 = "-----BEGIN RSA PRIVATE KEY-----"
        $cert4 = "-----BEGIN PRIVATE KEY-----"
        $cert5 = "-----BEGIN DH PARAMETERS-----"
        $cert6 = "-----BEGIN PGP"

    condition:
        $b64 and any of ($exec*) and not any of ($cert*)
}

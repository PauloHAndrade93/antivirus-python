@echo off
rem =====================================================================
rem AV-Py - launcher interativo
rem   Duplo clique neste arquivo (ou execute no CMD) para abrir o menu.
rem   Qualquer comando pode tambem ser rodado direto: python av.py ...
rem =====================================================================

setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 > nul
title AV-Py - Antivirus defensivo em Python

rem Vai sempre para a pasta onde este .bat esta (mesmo em duplo clique)
cd /d "%~dp0"

rem ---- checa Python ---------------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python nao encontrado no PATH.
    echo        Instale em https://www.python.org/downloads/ e marque "Add to PATH".
    pause
    exit /b 1
)

rem ---- checa dependencias (so instala na primeira vez) ----------------
if not exist ".deps-ok" (
    echo [i] Primeira execucao: instalando dependencias...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERRO] Falha ao instalar dependencias. Verifique pip e sua conexao.
        pause
        exit /b 1
    )
    echo ok > ".deps-ok"
)

:menu
cls
echo ======================================================================
echo                   AV-Py - Antivirus defensivo em Python
echo ======================================================================
echo.
echo   SCAN (hash + YARA)
echo     1. Escanear pasta Downloads
echo     2. Escanear outra pasta...
echo     3. Escanear pasta Downloads com --quarantine (isola o que achar)
echo     4. Escanear pasta com segunda opiniao do VirusTotal (--vt)
echo.
echo   FULL SCAN (drives inteiros)
echo    13. Escanear TODOS os drives (HD + SSD + pendrives)
echo    14. Escanear apenas pendrives / drives USB
echo    15. Escanear um drive especifico...
echo    16. Escanear TODOS os drives com quarentena automatica
echo.
echo   MONITORAMENTO
echo     5. Snapshot de conexoes de rede suspeitas
echo     6. Observar beaconing (90s)
echo     7. Vigiar Documents + Desktop contra ransomware (Ctrl+C para parar)
echo     8. Vigiar outra pasta contra ransomware...
echo.
echo   AUDITORIA
echo     9. Auditar persistencia (so suspeitos)
echo    10. Auditar persistencia (inventario completo)
echo.
echo   VIRUSTOTAL
echo    11. Consultar hash, IP ou dominio no VirusTotal
echo.
echo   QUARENTENA
echo    12. Listar arquivos em quarentena
echo.
echo     0. Sair
echo.
set "opcao="
set /p "opcao=Escolha uma opcao: "

if "%opcao%"=="1"  goto scan_downloads
if "%opcao%"=="2"  goto scan_pasta
if "%opcao%"=="3"  goto scan_quarentena
if "%opcao%"=="4"  goto scan_vt
if "%opcao%"=="5"  goto netmon
if "%opcao%"=="6"  goto netmon_beacon
if "%opcao%"=="7"  goto watch_padrao
if "%opcao%"=="8"  goto watch_pasta
if "%opcao%"=="9"  goto persist
if "%opcao%"=="10" goto persist_all
if "%opcao%"=="11" goto vt
if "%opcao%"=="12" goto quarantine_list
if "%opcao%"=="13" goto fullscan_todos
if "%opcao%"=="14" goto fullscan_usb
if "%opcao%"=="15" goto fullscan_drive
if "%opcao%"=="16" goto fullscan_quarentena
if "%opcao%"=="0"  goto sair

echo [!] Opcao invalida.
timeout /t 2 > nul
goto menu

rem ---- SCAN -----------------------------------------------------------

:scan_downloads
python av.py scan "%USERPROFILE%\Downloads"
goto pausa

:scan_pasta
set "pasta="
set /p "pasta=Caminho da pasta: "
if "!pasta!"=="" goto menu
python av.py scan "!pasta!"
goto pausa

:scan_quarentena
echo [i] Scan em %USERPROFILE%\Downloads com quarentena automatica.
python av.py scan "%USERPROFILE%\Downloads" --quarantine
goto pausa

:scan_vt
if "%VT_API_KEY%"=="" (
    echo [!] VT_API_KEY nao esta no ambiente. Configure antes:
    echo       setx VT_API_KEY "sua_chave"    ^(persistente, abra um CMD novo depois^)
    echo       $env:VT_API_KEY = "sua_chave"  ^(so para a sessao^)
    goto pausa
)
set "pasta="
set /p "pasta=Caminho da pasta (ENTER para Downloads): "
if "!pasta!"=="" set "pasta=%USERPROFILE%\Downloads"
python av.py scan "!pasta!" --vt
goto pausa

rem ---- NETMON ---------------------------------------------------------

:netmon
python av.py netmon
goto pausa

:netmon_beacon
echo [i] Vai observar beaconing por 90 segundos. Ctrl+C aborta.
python av.py netmon --beacon
goto pausa

rem ---- WATCH (ransomware) --------------------------------------------

:watch_padrao
echo [i] Vigiando Documents e Desktop. Ctrl+C para parar.
python av.py watch "%USERPROFILE%\Documents" "%USERPROFILE%\Desktop"
goto pausa

:watch_pasta
set "pasta="
set /p "pasta=Caminho da pasta: "
if "!pasta!"=="" goto menu
python av.py watch "!pasta!"
goto pausa

rem ---- PERSISTENCIA ---------------------------------------------------

:persist
python av.py persist
goto pausa

:persist_all
python av.py persist --all
goto pausa

rem ---- VIRUSTOTAL -----------------------------------------------------

:vt
if "%VT_API_KEY%"=="" (
    echo [!] VT_API_KEY nao esta no ambiente. Configure antes:
    echo       setx VT_API_KEY "sua_chave"    ^(persistente, abra um CMD novo depois^)
    goto pausa
)
set "alvo="
set /p "alvo=Hash, IP ou dominio: "
if "!alvo!"=="" goto menu
python av.py vt "!alvo!"
goto pausa

rem ---- QUARENTENA -----------------------------------------------------

:quarantine_list
python av.py quarantine --list
goto pausa

rem ---- FULLSCAN -------------------------------------------------------

:fullscan_todos
echo [i] Full scan em todos os drives fixos e removiveis. Vai demorar.
echo     Ctrl+C aborta. O relatorio final vai para logs\fullscan_*.log.
python av.py fullscan
goto pausa

:fullscan_usb
echo [i] Full scan APENAS em drives removiveis (pendrives, HD USB, SD).
python av.py fullscan --usb-only
goto pausa

:fullscan_drive
set "letra="
set /p "letra=Letra do drive (ex: C, E): "
if "!letra!"=="" goto menu
python av.py fullscan --drive "!letra!:"
goto pausa

:fullscan_quarentena
echo [i] Full scan com quarentena automatica (isola o que achar).
echo     Revise a pasta quarantine\ antes de apagar.
python av.py fullscan --quarantine
goto pausa

rem ---- CONTROLE -------------------------------------------------------

:pausa
echo.
pause
goto menu

:sair
endlocal
exit /b 0

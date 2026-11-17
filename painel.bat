@echo off
rem =====================================================================
rem AV-Py - abre o painel web local (http://127.0.0.1:8765)
rem   Duplo clique. Feche esta janela (ou Ctrl+C) para encerrar o painel.
rem =====================================================================
setlocal
chcp 65001 > nul
title AV-Py - Painel
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python nao encontrado no PATH.
    pause
    exit /b 1
)

python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [i] Instalando dependencias do painel...
    python -m pip install -r requirements.txt
)

python web\app.py
endlocal

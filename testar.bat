@echo off
rem Roda a suite de testes do AV-Py a partir da pasta certa,
rem nao importa de onde o arquivo foi aberto.
setlocal
chcp 65001 > nul
cd /d "%~dp0"
python -c "import pytest, hypothesis" >nul 2>&1 || python -m pip install -r requirements-dev.txt
python -m pytest
set "codigo=%errorlevel%"
echo.
if "%codigo%"=="0" (echo [+] Todos os testes passaram.) else (echo [!] Ha testes falhando - veja acima.)
pause
exit /b %codigo%

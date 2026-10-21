@echo off
setlocal
cd /d "%~dp0"
title OsintHunter
set PYTHONUTF8=1

if not exist ".venv\Scripts\python.exe" (
    echo [OsintHunter] Creando entorno virtual...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo No se encontro Python 3. Instalalo desde https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

echo [OsintHunter] Comprobando dependencias...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
    echo Error instalando dependencias.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m app %*
pause

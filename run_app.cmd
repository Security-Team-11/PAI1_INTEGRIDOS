@echo off
title INTEGRIDOS - Banco Seguro

echo ===============================
echo   INTEGRIDOS - DEPLOY SCRIPT
echo ===============================
echo.

REM ---- Comprobar Python ----
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python no esta instalado o no esta en PATH.
    pause
    exit /b
)

REM ---- Crear entorno virtual si no existe ----
if not exist venv (
    echo Creando entorno virtual...
    python -m venv venv
)

REM ---- Activar entorno virtual ----
call venv\Scripts\activate

REM ---- Actualizar pip ----
python -m pip install --upgrade pip

REM ---- Instalar dependencias ----
echo Instalando dependencias...
pip install -r requirements.txt

echo.
echo ===============================
echo   Iniciando Servidor...
echo ===============================

REM ---- Lanzar servidor en nueva ventana ----
start "Servidor Banco Seguro" cmd /k "call venv\Scripts\activate && python server\server.py"

REM ---- Esperar 3 segundos para que el servidor arranque ----
timeout /t 3 >nul

echo.
echo ===============================
echo   Iniciando Cliente...
echo ===============================

REM ---- Lanzar cliente ----
start "Cliente Banco Seguro" cmd /k "call venv\Scripts\activate && python client\client.py"

echo.
echo Aplicacion iniciada correctamente.
pause
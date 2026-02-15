@echo off
setlocal enabledelayedexpansion
title CatRealm Self-Hosted Server
color 0A

echo ========================================
echo   CatRealm Self-Hosted Server Startup
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [ERROR] Node.js is not installed!
    echo.
    echo Starting dependency installer...
    echo.
    timeout /t 2 /nobreak >nul
    start "CatRealm Dependency Installer" "%~dp0depinstaller.bat"
    echo.
    echo Please wait for the installer to complete, then run Start.bat again.
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

REM Check Node.js version
echo [INFO] Checking Node.js version...
node -v
echo.

REM Get major version number
for /f "tokens=1 delims=.v" %%a in ('node -v') do set NODE_MAJOR=%%a

REM Check if version is below 20
if %NODE_MAJOR% LSS 20 (
    color 0E
    echo [WARNING] Your Node.js version is outdated!
    echo Minimum required: v20.x
    echo Recommended: v24.x or higher
    echo.
    echo Starting dependency installer to upgrade...
    echo.
    timeout /t 2 /nobreak >nul
    start "CatRealm Dependency Installer" "%~dp0depinstaller.bat"
    echo.
    echo Please wait for the installer to complete, then run Start.bat again.
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

set "PYTHON_EXE="

for /f "delims=" %%p in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
if not defined PYTHON_EXE (
    for /f "delims=" %%p in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
)

REM Check if .env file exists
if not exist ".env" (
    echo [WARNING] .env file not found!
    echo.
    if exist ".env.win.example" (
        echo Creating .env from .env.win.example ^(Windows defaults^)...
        copy ".env.win.example" ".env" >nul
        echo [SUCCESS] Created .env file with Windows-optimized settings
        echo.
        echo IMPORTANT: Please edit .env file with your settings!
        echo Press any key to open .env in notepad...
        pause >nul
        notepad .env
        echo.
        echo After configuring .env, press any key to continue...
        pause >nul
    ) else if exist ".env.example" (
        echo Creating .env from .env.example...
        copy ".env.example" ".env" >nul
        echo [SUCCESS] Created .env file
        echo.
        echo IMPORTANT: Please edit .env file with your settings!
        echo Press any key to open .env in notepad...
        pause >nul
        notepad .env
        echo.
        echo After configuring .env, press any key to continue...
        pause >nul
    ) else (
        color 0E
        echo [ERROR] No .env.win.example or .env.example found!
        echo Please create a .env file manually.
        echo.
        echo Press any key to exit...
        pause >nul
        exit /b 1
    )
)

REM Check if dependencies are installed and complete
set "NEED_NPM_INSTALL=0"
if not exist "node_modules" (
    set "NEED_NPM_INSTALL=1"
) else (
    call node -e "require.resolve('dotenv'); require.resolve('express'); require.resolve('better-sqlite3')" >nul 2>&1
    if errorlevel 1 set "NEED_NPM_INSTALL=1"
)

if "!NEED_NPM_INSTALL!"=="1" (
    echo [INFO] Installing or repairing dependencies...
    echo This may take a few minutes...
    echo.
    if defined PYTHON_EXE set "PYTHON=!PYTHON_EXE!"
    call npm install --omit=dev
    if errorlevel 1 (
        color 0C
        echo.
        echo [ERROR] Failed to install dependencies!
        echo Press any key to exit...
        pause >nul
        exit /b 1
    )
    echo.
    echo [SUCCESS] Dependencies installed!
    echo.
)

REM Check if src/index.js exists
if not exist "src\index.js" (
    color 0C
    echo [ERROR] src/index.js not found!
    echo Make sure you're running this from the CatRealm-SelfHostableServer directory.
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo ========================================
echo   Starting CatRealm Server...
echo ========================================
echo.
echo Server will start in 3 seconds...
timeout /t 3 /nobreak >nul
echo.

REM Start the server
node src/index.js

REM If server crashes or exits
echo.
color 0E
echo ========================================
echo   Server Stopped
echo ========================================
echo.
echo Press any key to restart, or close this window to exit...
pause >nul

REM Restart
goto :eof
cls
Start.bat


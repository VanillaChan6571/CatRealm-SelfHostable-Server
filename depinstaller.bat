@echo off
setlocal enabledelayedexpansion
title CatRealm Dependency Installer
color 0E

echo ========================================
echo   CatRealm Dependency Installer
echo ========================================
echo.

REM Check if winget is available
where winget >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] Windows Package Manager ^(winget^) is not available!
    echo.
    echo Winget is required for automatic installation.
    echo It's included in Windows 10 ^(version 1809+^) and Windows 11.
    echo.
    echo Please install these manually:
    echo - Node.js LTS: https://nodejs.org/
    echo - Python 3: https://www.python.org/downloads/
    echo - Visual Studio Build Tools ^(C++^): https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

set "HAD_ERRORS=0"
set "INSTALL_PYTHON=1"

echo [INFO] This installer will ensure these dependencies exist:
echo - Node.js LTS
echo - Python 3
echo - Visual Studio C++ Build Tools
echo - node-gyp (global npm package)
echo.
echo Some installers may trigger UAC and take several minutes.
echo.

call :install_if_missing "OpenJS.NodeJS.LTS" "Node.js LTS"
echo Install Python 3 now? Required for native module builds on Node 24.
choice /c YN /n /m "Install Python [Y/N]: "
if errorlevel 2 set "INSTALL_PYTHON=0"
if errorlevel 1 set "INSTALL_PYTHON=1"
if "!INSTALL_PYTHON!"=="0" goto :skip_python_install
call :ensure_python
goto :after_python_install

:skip_python_install
echo [INFO] Skipping Python install by user choice.
echo.

:after_python_install
call :install_build_tools
call :configure_npm_python
call :install_node_gyp

echo.
echo ========================================
echo   Installation Summary
echo ========================================
if "!HAD_ERRORS!"=="0" (
    color 0A
    echo [SUCCESS] Dependency installation completed.
) else (
    color 0E
    echo [WARNING] Some steps failed. Review messages above.
)
echo.
echo Please close this window and run Start.bat again.
echo.
echo Press any key to exit...
pause >nul
exit /b 0

:install_if_missing
set "PKG_ID=%~1"
set "PKG_LABEL=%~2"
winget list --id "!PKG_ID!" --source winget >nul 2>&1
if not errorlevel 1 (
    echo [OK] !PKG_LABEL! is already installed.
    goto :eof
)

echo [INFO] Installing !PKG_LABEL!...
winget install --id "!PKG_ID!" --source winget --silent --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to install !PKG_LABEL!.
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] Installed !PKG_LABEL!.
)
echo.
goto :eof

:install_build_tools
winget list --id Microsoft.VisualStudio.2022.BuildTools --source winget >nul 2>&1
if not errorlevel 1 (
    echo [OK] Visual Studio Build Tools is already installed.
    echo.
    goto :eof
)

echo [INFO] Installing Visual Studio Build Tools (C++ workload)...
winget install --id Microsoft.VisualStudio.2022.BuildTools --source winget --silent --accept-package-agreements --accept-source-agreements --override "--wait --quiet --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to install Visual Studio Build Tools.
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] Installed Visual Studio Build Tools.
)
echo.
goto :eof

:ensure_python
set "PYTHON_EXE="
call :detect_python_exe
if defined PYTHON_EXE (
    echo [OK] Python detected: !PYTHON_EXE!
    echo.
    goto :eof
)

echo [INFO] Installing Python 3.12...
winget install --id "Python.Python.3.12" --source winget --silent --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to install Python 3.12.
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

set "PYTHON_EXE="
call :detect_python_exe
if defined PYTHON_EXE (
    echo [SUCCESS] Installed Python 3.12.
) else (
    color 0E
    echo [WARNING] Python install completed, but executable was not detected yet.
    echo [WARNING] Open a new terminal and run Start.bat again.
    set "HAD_ERRORS=1"
)
echo.
goto :eof

:detect_python_exe
for /f "delims=" %%p in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
if defined PYTHON_EXE goto :eof

for /f "delims=" %%p in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
if defined PYTHON_EXE goto :eof

for /f "tokens=2,*" %%a in ('reg query "HKCU\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%b"
)
if defined PYTHON_EXE goto :eof

for /f "tokens=2,*" %%a in ('reg query "HKLM\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%b"
)
if defined PYTHON_EXE goto :eof

for %%p in (
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles(x86)%\Python313-32\python.exe"
    "%ProgramFiles(x86)%\Python312-32\python.exe"
    "%ProgramFiles(x86)%\Python311-32\python.exe"
) do (
    if exist "%%~p" (
        set "PYTHON_EXE=%%~p"
        goto :eof
    )
)
goto :eof

:configure_npm_python
set "PYTHON_EXE="
call :detect_python_exe

if not defined PYTHON_EXE (
    if "!INSTALL_PYTHON!"=="0" (
        echo [INFO] Python configuration skipped ^(Python install was declined^).
    ) else (
        color 0E
        echo [WARNING] Python executable not found in PATH. Skipping npm python configuration.
        set "HAD_ERRORS=1"
    )
    echo.
    goto :eof
)

set "PYTHON=!PYTHON_EXE!"
setx PYTHON "!PYTHON_EXE!" >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to persist PYTHON environment variable.
    echo [WARNING] Current installer session will still use: !PYTHON_EXE!
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] PYTHON environment variable configured: !PYTHON_EXE!
)
echo.
goto :eof

:install_node_gyp
where npm >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARNING] npm was not found in PATH. Could not install node-gyp.
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

call npm install -g node-gyp >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to install node-gyp globally.
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] node-gyp installed globally.
)
echo.
goto :eof

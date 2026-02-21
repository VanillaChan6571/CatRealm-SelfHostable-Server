@echo off
setlocal enabledelayedexpansion
title CatRealm Dependency Installer
color 0E

echo ========================================
echo   CatRealm Dependency Installer
echo ========================================
echo.

REM Check if winget is available
set "HAS_WINGET=0"
where winget >nul 2>&1
if not errorlevel 1 set "HAS_WINGET=1"

if "!HAS_WINGET!"=="0" (
    echo [INFO] Windows Package Manager ^(winget^) is not available.
    echo [INFO] Using direct-download fallback ^(works on LTSC/IoT editions^).
    echo.
)

set "HAD_ERRORS=0"
set "INSTALL_PYTHON=1"
set "TEMP_DIR=%TEMP%\CatRealmInstall"
if not exist "!TEMP_DIR!" mkdir "!TEMP_DIR!"

echo [INFO] This installer will ensure these dependencies exist:
echo - Git
echo - Node.js LTS
echo - Python 3
echo - Visual Studio C++ Build Tools
echo - node-gyp (global npm package)
echo.
echo Some installers may trigger UAC and take several minutes.
echo.

call :install_git
call :ensure_git_in_path
call :clone_repo_if_needed
call :install_node
call :ensure_node_installed
call :ensure_node_in_path
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
call :ensure_npm_in_path
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

:install_git
where git >nul 2>&1
if not errorlevel 1 (
    echo [OK] Git is already installed.
    echo.
    goto :eof
)

REM Check common Git install locations
set "GIT_FOUND=0"
for %%g in (
    "%ProgramFiles%\Git\cmd\git.exe"
    "%ProgramFiles(x86)%\Git\cmd\git.exe"
    "%LocalAppData%\Programs\Git\cmd\git.exe"
    "%ProgramW6432%\Git\cmd\git.exe"
) do (
    if exist "%%~g" set "GIT_FOUND=1"
)
if "!GIT_FOUND!"=="1" (
    echo [OK] Git is already installed ^(not in PATH yet, will fix^).
    echo.
    goto :eof
)

if "!HAS_WINGET!"=="1" (
    echo [INFO] Installing Git via winget...
    winget install --id "Git.Git" --source winget --silent --accept-package-agreements --accept-source-agreements
    if not errorlevel 1 (
        echo [SUCCESS] Installed Git.
        echo.
        goto :eof
    )
    echo [WARNING] winget install failed, trying direct download...
)

echo [INFO] Downloading Git installer...
set "GIT_INSTALLER=!TEMP_DIR!\git-installer.exe"
powershell -NoProfile -Command "try { $url = 'https://github.com/git-for-windows/git/releases/latest'; $r = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue 2>$null; $loc = $r.Headers.Location; if (-not $loc) { $r2 = Invoke-WebRequest -Uri $url -UseBasicParsing; $loc = ($r2.Links | Where-Object { $_.href -match 'Git-.*64-bit\.exe$' } | Select-Object -First 1).href }; if ($loc -match '/tag/(.+)') { $tag = $Matches[1]; $ver = $tag -replace '^v',''; $ver = $ver -replace '\.windows\.\d+$',''; $dlUrl = \"https://github.com/git-for-windows/git/releases/download/$tag/Git-$ver-64-bit.exe\"; Write-Host \"Downloading $dlUrl\"; Invoke-WebRequest -Uri $dlUrl -OutFile '!GIT_INSTALLER!' -UseBasicParsing } else { exit 1 }; exit 0 } catch { Write-Host \"Error: $_\"; exit 1 }"
if not exist "!GIT_INSTALLER!" (
    echo [INFO] Dynamic URL failed, trying known-good Git v2.47.1...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe' -OutFile '!GIT_INSTALLER!' -UseBasicParsing"
)
if not exist "!GIT_INSTALLER!" (
    color 0E
    echo [WARNING] Failed to download Git installer.
    echo [WARNING] Please install Git manually from: https://git-scm.com/download/win
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

echo [INFO] Running Git installer...
"!GIT_INSTALLER!" /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
if errorlevel 1 (
    echo [INFO] Silent install failed, launching interactive installer...
    "!GIT_INSTALLER!"
)
del "!GIT_INSTALLER!" >nul 2>&1
echo.
goto :eof

:ensure_git_in_path
where git >nul 2>&1
if not errorlevel 1 goto :eof

REM Try to find git and add it to PATH for this session
for %%g in (
    "%ProgramFiles%\Git\cmd"
    "%ProgramFiles(x86)%\Git\cmd"
    "%LocalAppData%\Programs\Git\cmd"
    "%ProgramW6432%\Git\cmd"
) do (
    if exist "%%~g\git.exe" (
        set "PATH=%%~g;!PATH!"
        echo [INFO] Added Git to PATH for this session: %%~g
        echo.
        goto :eof
    )
)
goto :eof

:clone_repo_if_needed
set "REPO_URL=https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git"
set "REPO_BRANCH=main"

where git >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARNING] Git is not available. Cannot clone or initialize the repository.
    echo [WARNING] Please install Git from https://git-scm.com/download/win and re-run.
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

REM Case 1: Files exist but .git is missing — init repo in-place
if exist "%~dp0src\index.js" (
    if exist "%~dp0.git" (
        echo [OK] CatRealm server files and .git detected.
        echo.
        goto :eof
    )
    echo [INFO] Server files found but .git folder is missing. Initializing repository in-place...
    git -C "%~dp0." init
    if errorlevel 1 (
        color 0E
        echo [WARNING] git init failed.
        set "HAD_ERRORS=1"
        echo.
        goto :eof
    )
    git -C "%~dp0." remote remove origin >nul 2>&1
    git -C "%~dp0." remote add origin "!REPO_URL!"
    if errorlevel 1 (
        color 0E
        echo [WARNING] Failed to add remote origin.
        set "HAD_ERRORS=1"
        echo.
        goto :eof
    )
    git -C "%~dp0." fetch origin !REPO_BRANCH!
    if errorlevel 1 (
        color 0E
        echo [WARNING] Failed to fetch from remote.
        set "HAD_ERRORS=1"
        echo.
        goto :eof
    )
    git -C "%~dp0." checkout -f -B !REPO_BRANCH! origin/!REPO_BRANCH!
    if errorlevel 1 (
        color 0E
        echo [WARNING] Failed to checkout remote branch.
        set "HAD_ERRORS=1"
        echo.
        goto :eof
    )
    echo [SUCCESS] .git initialized and linked to remote.
    echo.
    goto :eof
)

REM Case 2: No files at all — full clone
echo [INFO] CatRealm server files not found in: %~dp0
echo [INFO] Cloning CatRealm repository...
set "CLONE_DIR=%~dp0CatRealm-SelfHostable-Server"
git clone "!REPO_URL!" "!CLONE_DIR!"
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to clone repository.
    echo [WARNING] Please clone manually: git clone !REPO_URL!
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] Cloned CatRealm to: !CLONE_DIR!
    echo [INFO] After this installer finishes, run Start.bat from that folder.
)
echo.
goto :eof

:install_node
set "NODE_ROOT="
call :detect_node_root
if defined NODE_ROOT (
    echo [OK] Node.js is already installed.
    echo.
    goto :eof
)

if "!HAS_WINGET!"=="1" (
    echo [INFO] Installing Node.js LTS via winget...
    winget install --id "OpenJS.NodeJS.LTS" --source winget --silent --accept-package-agreements --accept-source-agreements
    if not errorlevel 1 (
        echo [SUCCESS] Installed Node.js LTS.
        echo.
        goto :eof
    )
    echo [WARNING] winget install failed, trying direct download...
)

echo [INFO] Downloading Node.js LTS installer...
set "NODE_MSI=!TEMP_DIR!\node-lts.msi"
powershell -NoProfile -Command "try { $url = (Invoke-WebRequest -Uri 'https://nodejs.org/en/download/' -UseBasicParsing).Links | Where-Object { $_.href -match '\.msi$' -and $_.href -match 'x64' } | Select-Object -First 1 -ExpandProperty href; if (-not $url) { $url = 'https://nodejs.org/dist/v24.13.1/node-v24.13.1-x64.msi' }; if ($url -notmatch '^https?://') { $url = 'https://nodejs.org' + $url }; Write-Host \"Downloading $url\"; Invoke-WebRequest -Uri $url -OutFile '%NODE_MSI%' -UseBasicParsing; exit 0 } catch { Write-Host \"Download failed: $_\"; exit 1 }"
if errorlevel 1 (
    echo [INFO] Trying known-good Node.js v24.13.1 URL...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v24.13.1/node-v24.13.1-x64.msi' -OutFile '!NODE_MSI!' -UseBasicParsing"
)
if not exist "!NODE_MSI!" (
    color 0E
    echo [WARNING] Failed to download Node.js installer.
    echo [WARNING] Please install Node.js LTS manually from: https://nodejs.org/
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

echo [INFO] Running Node.js installer (may require admin privileges)...
msiexec /i "!NODE_MSI!" /qn /norestart
if errorlevel 1 (
    echo [INFO] Silent install failed, launching interactive installer...
    msiexec /i "!NODE_MSI!"
)
del "!NODE_MSI!" >nul 2>&1
echo.
goto :eof

:ensure_node_installed
set "NODE_ROOT="
call :detect_node_root
if defined NODE_ROOT goto :eof

echo [WARNING] Node.js LTS was not detected after install attempt.
echo [INFO] Retrying Node.js LTS install...

if "!HAS_WINGET!"=="1" (
    winget install --id "OpenJS.NodeJS.LTS" --source winget --silent --accept-package-agreements --accept-source-agreements
    if not errorlevel 1 (
        set "NODE_ROOT="
        call :detect_node_root
        if defined NODE_ROOT (
            echo [SUCCESS] Node.js LTS detected after retry.
            echo.
            goto :eof
        )
    )
)

color 0E
echo [WARNING] Node.js still not detected. Please install manually from https://nodejs.org/
set "HAD_ERRORS=1"
echo.
goto :eof

:install_build_tools
REM Check if cl.exe or VS Build Tools are present
set "HAS_BUILD_TOOLS=0"
if "!HAS_WINGET!"=="1" (
    winget list --id Microsoft.VisualStudio.2022.BuildTools --source winget >nul 2>&1
    if not errorlevel 1 set "HAS_BUILD_TOOLS=1"
)
if "!HAS_BUILD_TOOLS!"=="0" (
    where cl >nul 2>&1
    if not errorlevel 1 set "HAS_BUILD_TOOLS=1"
)
if "!HAS_BUILD_TOOLS!"=="0" (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" set "HAS_BUILD_TOOLS=1"
)
if "!HAS_BUILD_TOOLS!"=="0" (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" set "HAS_BUILD_TOOLS=1"
)
if "!HAS_BUILD_TOOLS!"=="1" (
    echo [OK] Visual Studio Build Tools is already installed.
    echo.
    goto :eof
)

if "!HAS_WINGET!"=="1" (
    echo [INFO] Installing Visual Studio Build Tools via winget (C++ workload)...
    winget install --id Microsoft.VisualStudio.2022.BuildTools --source winget --silent --accept-package-agreements --accept-source-agreements --override "--wait --quiet --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    if not errorlevel 1 (
        echo [SUCCESS] Installed Visual Studio Build Tools.
        echo.
        goto :eof
    )
    echo [WARNING] winget install failed, trying direct download...
)

echo [INFO] Downloading Visual Studio Build Tools installer...
set "VS_INSTALLER=!TEMP_DIR!\vs_buildtools.exe"
powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_buildtools.exe' -OutFile '!VS_INSTALLER!' -UseBasicParsing"
if not exist "!VS_INSTALLER!" (
    color 0E
    echo [WARNING] Failed to download VS Build Tools installer.
    echo [WARNING] Please install manually from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

echo [INFO] Running VS Build Tools installer (this may take several minutes)...
"!VS_INSTALLER!" --wait --quiet --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
if errorlevel 1 (
    echo [INFO] Silent install failed, launching interactive installer...
    "!VS_INSTALLER!" --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
)
del "!VS_INSTALLER!" >nul 2>&1
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

if "!HAS_WINGET!"=="1" (
    echo [INFO] Installing Python 3.12 via winget...
    winget install --id "Python.Python.3.12" --source winget --silent --accept-package-agreements --accept-source-agreements
    if not errorlevel 1 (
        set "PYTHON_EXE="
        call :detect_python_exe
        if defined PYTHON_EXE (
            echo [SUCCESS] Installed Python 3.12.
            echo.
            goto :eof
        )
    )
    echo [WARNING] winget install failed, trying direct download...
)

echo [INFO] Downloading Python 3.12 installer...
set "PY_INSTALLER=!TEMP_DIR!\python-3.12.msi"
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe' -OutFile '!PY_INSTALLER!' -UseBasicParsing; exit 0 } catch { exit 1 }"
if not exist "!PY_INSTALLER!" (
    color 0E
    echo [WARNING] Failed to download Python installer.
    echo [WARNING] Please install manually from: https://www.python.org/downloads/
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

echo [INFO] Running Python installer...
"!PY_INSTALLER!" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
if errorlevel 1 (
    echo [INFO] Silent install failed, launching interactive installer...
    "!PY_INSTALLER!" InstallAllUsers=1 PrependPath=1 Include_test=0
)
del "!PY_INSTALLER!" >nul 2>&1

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
set "NPM_CMD="
call :detect_npm_cmd

if not defined NPM_CMD (
    color 0E
    echo [WARNING] npm was not found in PATH. Could not install node-gyp.
    set "HAD_ERRORS=1"
    echo.
    goto :eof
)

call "!NPM_CMD!" install -g node-gyp >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARNING] Failed to install node-gyp globally.
    set "HAD_ERRORS=1"
) else (
    echo [SUCCESS] node-gyp installed globally.
)
echo.
goto :eof

:ensure_npm_in_path
set "NPM_CMD="
call :detect_npm_cmd
if defined NPM_CMD goto :eof

set "NODE_ROOT="
call :detect_node_root
if not defined NODE_ROOT goto :eof

if exist "!NODE_ROOT!\npm.cmd" (
    set "PATH=!NODE_ROOT!;!PATH!"
)
goto :eof

:ensure_node_in_path
set "NODE_ROOT="
call :detect_node_root
if not defined NODE_ROOT goto :eof

where node >nul 2>&1
if not errorlevel 1 goto :eof

set "PATH=!NODE_ROOT!;!PATH!"
goto :eof

:detect_npm_cmd
for /f "delims=" %%p in ('node -p "process.execPath" 2^>nul') do (
    if not defined NPM_CMD if exist "%%~dpnpm.cmd" set "NPM_CMD=%%~dpnpm.cmd"
)
if defined NPM_CMD goto :eof

for /f "delims=" %%p in ('where npm 2^>nul') do (
    if not defined NPM_CMD set "NPM_CMD=%%p"
)
if defined NPM_CMD goto :eof

if defined NVM_SYMLINK if exist "%NVM_SYMLINK%\npm.cmd" set "NPM_CMD=%NVM_SYMLINK%\npm.cmd"
if defined NPM_CMD goto :eof

if exist "%ProgramW6432%\nodejs\npm.cmd" set "NPM_CMD=%ProgramW6432%\nodejs\npm.cmd"
if defined NPM_CMD goto :eof

if exist "%ProgramFiles%\nodejs\npm.cmd" set "NPM_CMD=%ProgramFiles%\nodejs\npm.cmd"
if defined NPM_CMD goto :eof

if exist "%ProgramFiles(x86)%\nodejs\npm.cmd" set "NPM_CMD=%ProgramFiles(x86)%\nodejs\npm.cmd"
if defined NPM_CMD goto :eof

if exist "%LocalAppData%\Programs\nodejs\npm.cmd" set "NPM_CMD=%LocalAppData%\Programs\nodejs\npm.cmd"
if defined NPM_CMD goto :eof
goto :eof

:detect_node_root
set "NODE_ROOT="
for /f "delims=" %%p in ('node -p "process.execPath" 2^>nul') do (
    if not defined NODE_ROOT set "NODE_ROOT=%%~dp"
)
if defined NODE_ROOT goto :eof

for /f "delims=" %%p in ('where node 2^>nul') do (
    if not defined NODE_ROOT set "NODE_ROOT=%%~dp"
)
if defined NODE_ROOT goto :eof

for /f "tokens=2,*" %%a in ('reg query "HKLM\Software\Node.js" /v InstallPath 2^>nul ^| findstr /i "InstallPath"') do (
    if not defined NODE_ROOT set "NODE_ROOT=%%b"
)
if defined NODE_ROOT goto :eof

for /f "tokens=2,*" %%a in ('reg query "HKCU\Software\Node.js" /v InstallPath 2^>nul ^| findstr /i "InstallPath"') do (
    if not defined NODE_ROOT set "NODE_ROOT=%%b"
)
if defined NODE_ROOT goto :eof

if exist "%ProgramW6432%\nodejs\node.exe" set "NODE_ROOT=%ProgramW6432%\nodejs"
if defined NODE_ROOT goto :eof

if exist "%ProgramFiles%\nodejs\node.exe" set "NODE_ROOT=%ProgramFiles%\nodejs"
if defined NODE_ROOT goto :eof

if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "NODE_ROOT=%ProgramFiles(x86)%\nodejs"
if defined NODE_ROOT goto :eof

if exist "%LocalAppData%\Programs\nodejs\node.exe" set "NODE_ROOT=%LocalAppData%\Programs\nodejs"
if defined NODE_ROOT goto :eof
goto :eof

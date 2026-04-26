@echo off
setlocal EnableExtensions EnableDelayedExpansion

title G.A.L - Gamers As Legions Launcher
color 0A
cd /d "%~dp0"

echo.
echo ========================================
echo     G.A.L - Gamers As Legions
echo     System Optimization Tool
echo ========================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.7 or higher from python.org
    echo.
    pause
    exit /b 1
)

:: Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Detected Python version: %PYTHON_VERSION%
echo.

:: Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges: Yes
) else (
    echo Administrator privileges: No
    echo WARNING: Some features require Administrator rights for full functionality.
    echo.
)

echo Step 1: Installing required dependencies...
echo.

:: Install dependencies from requirements.txt when available
if exist requirements.txt (
    echo Installing dependencies from requirements.txt...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo WARNING: requirements.txt install had issues.
        echo Falling back to individual package installation...
        echo.
        python -m pip install customtkinter
        python -m pip install psutil
        python -m pip install GPUtil
        python -m pip install wmi
        python -m pip install speedtest-cli
        python -m pip install Pillow
    )
) else (
    echo requirements.txt not found, installing dependencies individually...
    echo.
    python -m pip install customtkinter
    python -m pip install psutil
    python -m pip install GPUtil
    python -m pip install wmi
    python -m pip install speedtest-cli
    python -m pip install Pillow
)

echo.
echo Step 2: Verifying critical dependencies...
echo.

python -c "import customtkinter; print('customtkinter - OK')" 2>nul || echo customtkinter - MISSING
python -c "import psutil; print('psutil - OK')" 2>nul || echo psutil - MISSING
python -c "import GPUtil; print('GPUtil - OK')" 2>nul || echo GPUtil - MISSING
python -c "import wmi; print('wmi - OK')" 2>nul || echo wmi - MISSING
python -c "import speedtest; print('speedtest-cli - OK')" 2>nul || echo speedtest-cli - MISSING
python -c "from PIL import Image; print('Pillow - OK')" 2>nul || echo Pillow - MISSING

echo.
echo Step 3: Locating the latest G.A.L application...
echo.

set "MAIN_FILE="

:: Preferred filenames first
for %%F in (
    "Tools_v1.5.0_lrb-revert-added.pyw"
    "Tools_v1.4.9_bandwidth-menu-visible.pyw"
    "Tools_v1.4.8_bandwidth-in-tools-menu.pyw"
    "Tools_v1.4.7_bandwidth-key-create.pyw"
    "Tools_v1.4.6_bandwidth-warning-fixed-clean.pyw"
    "G.A.L_V1.2_updated.pyw"
    "G.A.L_V1.1.pyw"
    "G.A.L.pyw"
) do (
    if exist %%~F (
        set "MAIN_FILE=%%~F"
        goto :launch
    )
)

:: Fallback: first .pyw in the current folder
for %%i in (*.pyw) do (
    set "MAIN_FILE=%%i"
    goto :launch
)

:launch
if defined MAIN_FILE (
    echo Launching !MAIN_FILE!...
    echo.
    python "!MAIN_FILE!"
) else (
    echo ERROR: No Python .pyw file found to launch!
    echo Please ensure the G.A.L Python file is in the same directory.
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo     G.A.L Application Closed
echo ========================================
echo.
pause
endlocal

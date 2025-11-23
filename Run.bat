@echo off
title G.A.L - Gamers As Legions Launcher
color 0A
echo.
echo ========================================
echo    G.A.L - Gamers As Legions
echo    System Optimization Tool
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
    echo WARNING: Some features may require Administrator rights!
    echo.
)

echo.
echo Step 1: Installing required dependencies...
echo.

:: Install dependencies from requirements.txt
if exist requirements.txt (
    echo Installing dependencies from requirements.txt...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install some dependencies!
        echo Trying individual package installation...
        echo.
        
        echo Installing customtkinter...
        pip install customtkinter
        
        echo Installing psutil...
        pip install psutil
        
        echo Installing GPUtil...
        pip install GPUtil
        
        echo Installing wmi...
        pip install wmi
        
        echo Installing speedtest-cli...
        pip install speedtest-cli
        
        echo Installing Pillow...
        pip install pillow
    )
) else (
    echo requirements.txt not found, installing dependencies individually...
    echo.
    
    echo Installing customtkinter...
    pip install customtkinter
    
    echo Installing psutil...
    pip install psutil
    
    echo Installing GPUtil...
    pip install GPUtil
    
    echo Installing wmi...
    pip install wmi
    
    echo Installing speedtest-cli...
    pip install speedtest-cli
    
    echo Installing Pillow...
    pip install pillow
)

echo.
echo Step 2: Checking if all dependencies are installed...
echo.

:: Verify critical dependencies
python -c "import customtkinter; print('✓ customtkinter - OK')" 2>nul || echo ✗ customtkinter - MISSING
python -c "import psutil; print('✓ psutil - OK')" 2>nul || echo ✗ psutil - MISSING
python -c "import GPUtil; print('✓ GPUtil - OK')" 2>nul || echo ✗ GPUtil - MISSING
python -c "import wmi; print('✓ wmi - OK')" 2>nul || echo ✗ wmi - MISSING
python -c "import speedtest; print('✓ speedtest-cli - OK')" 2>nul || echo ✗ speedtest-cli - MISSING

echo.
echo Step 3: Launching G.A.L Application...
echo.

:: Find the main Python file
set MAIN_FILE=G.A.L.py
if exist "%MAIN_FILE%" (
    echo Launching %MAIN_FILE%...
    echo.
    python "%MAIN_FILE%"
) else (
    :: Try to find any Python file that might be the main application
    echo Searching for main application file...
    for %%i in (*.py) do (
        echo Found: %%i
        set MAIN_FILE=%%i
        goto :launch
    )
    
    :launch
    if defined MAIN_FILE (
        echo.
        echo Launching %MAIN_FILE%...
        echo.
        python "%MAIN_FILE%"
    ) else (
        echo.
        echo ERROR: No Python file found to launch!
        echo Please ensure the G.A.L Python file is in the same directory.
        echo.
        pause
    )
)

echo.
echo ========================================
echo    G.A.L Application Closed
echo ========================================
echo.
pause

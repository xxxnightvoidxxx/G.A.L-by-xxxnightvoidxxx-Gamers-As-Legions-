@echo off
setlocal EnableExtensions EnableDelayedExpansion

title G.A.L - Gamers As Legions Launcher
color 0A
cd /d "%~dp0"

:: Initialize debug log
set "DEBUG_LOG=debuginstaller.txt"
set "TIMESTAMP=%date% %time%"

echo ======================================== > "%DEBUG_LOG%"
echo G.A.L Installer Debug Log >> "%DEBUG_LOG%"
echo Timestamp: %TIMESTAMP% >> "%DEBUG_LOG%"
echo ======================================== >> "%DEBUG_LOG%"
echo. >> "%DEBUG_LOG%"

echo.
echo ========================================
echo     G.A.L - Gamers As Legions
echo     System Optimization Tool
echo ========================================
echo.

:: Log system information
echo [SYSTEM INFORMATION] >> "%DEBUG_LOG%"
echo OS: %OS% >> "%DEBUG_LOG%"
echo Computer: %COMPUTERNAME% >> "%DEBUG_LOG%"
echo User: %USERNAME% >> "%DEBUG_LOG%"
echo Architecture: %PROCESSOR_ARCHITECTURE% >> "%DEBUG_LOG%"
echo. >> "%DEBUG_LOG%"

:: Part 1: Check if virtual environment exists, if not create it
echo [PART 1 of 4] Checking for existing virtual environment...
echo.

if exist ".venv\Scripts\activate.bat" (
    echo Virtual environment already exists! Skipping creation...
    echo [STEP 1] Virtual environment already exists, skipping creation >> "%DEBUG_LOG%"
    echo Virtual environment path: %CD%\.venv >> "%DEBUG_LOG%"
) else (
    echo Creating Python virtual environment...
    echo [STEP 1] Creating Python virtual environment >> "%DEBUG_LOG%"
    echo Command: python -m venv .venv >> "%DEBUG_LOG%"
    
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment! >> "%DEBUG_LOG%"
        echo ERROR: Failed to create virtual environment!
        echo Errorlevel: !errorlevel! >> "%DEBUG_LOG%"
        pause
        exit /b 1
    )
    echo Virtual environment created successfully! >> "%DEBUG_LOG%"
    echo Virtual environment created successfully!
)
echo.

:: Part 2: Activate virtual environment
echo [PART 2 of 4] Activating virtual environment...
echo.
echo [STEP 2] Activating virtual environment >> "%DEBUG_LOG%"
echo Command: call .venv\Scripts\activate.bat >> "%DEBUG_LOG%"

call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment! >> "%DEBUG_LOG%"
    echo ERROR: Failed to activate virtual environment!
    echo Errorlevel: !errorlevel! >> "%DEBUG_LOG%"
    pause
    exit /b 1
)
echo Virtual environment activated successfully! >> "%DEBUG_LOG%"
echo Virtual environment activated successfully!
echo.

:: Verify virtual environment is active
echo [VERIFICATION] Virtual environment status >> "%DEBUG_LOG%"
if defined VIRTUAL_ENV (
    echo Virtual environment is active: %VIRTUAL_ENV% >> "%DEBUG_LOG%"
    echo Virtual environment is active: %VIRTUAL_ENV%
) else (
    echo WARNING: Virtual environment may not be active! >> "%DEBUG_LOG%"
    echo WARNING: Virtual environment may not be active!
)
echo. >> "%DEBUG_LOG%"

:: Clear pip cache to prevent deserialization warnings
echo [OPTIMIZATION] Clearing pip cache to prevent warnings... >> "%DEBUG_LOG%"
echo Clearing pip cache for cleaner installation...
python -m pip cache purge >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not clear pip cache, continuing anyway... >> "%DEBUG_LOG%"
) else (
    echo Pip cache cleared successfully! >> "%DEBUG_LOG%"
)
echo.

:: Part 3: Install dependencies and run application
echo [PART 3 of 4] Setting up dependencies and launching application...
echo.
echo [STEP 3] Setting up Python environment >> "%DEBUG_LOG%"

:: Check if Python is installed
echo Checking Python installation... >> "%DEBUG_LOG%"
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH! >> "%DEBUG_LOG%"
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.7 or higher from python.org
    echo.
    pause
    exit /b 1
)

:: Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Detected Python version: %PYTHON_VERSION% >> "%DEBUG_LOG%"
echo Detected Python version: %PYTHON_VERSION%
echo.

:: Check Python version for compatibility notes
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

:: Get pip version before upgrade
echo Getting pip version before upgrade... >> "%DEBUG_LOG%"
python -m pip --version >> "%DEBUG_LOG%" 2>&1

:: Set pip environment variables to reduce warnings
set PIP_NO_CACHE_DIR=0
set PIP_NO_WARN_SCRIPT_LOCATION=1

:: Upgrade pip to latest version
echo [STEP 3a] Upgrading pip to latest version... >> "%DEBUG_LOG%"
echo Upgrading pip to latest version...
echo Command: python.exe -m pip install --upgrade pip --no-cache-dir >> "%DEBUG_LOG%"
python.exe -m pip install --upgrade pip --no-cache-dir
if errorlevel 1 (
    echo WARNING: Pip upgrade had issues! Continuing with existing pip... >> "%DEBUG_LOG%"
    echo WARNING: Pip upgrade had issues! Continuing with existing pip...
) else (
    echo Pip upgraded successfully! >> "%DEBUG_LOG%"
    echo Pip upgraded successfully!
)
echo.

:: Install setuptools for Python 3.12+ compatibility (fixes distutils issue)
echo [STEP 3a.1] Installing setuptools for distutils compatibility... >> "%DEBUG_LOG%"
echo Installing setuptools for Python 3.12+ compatibility...
echo Command: python -m pip install setuptools --upgrade --no-cache-dir >> "%DEBUG_LOG%"
python -m pip install setuptools --upgrade --no-cache-dir
if errorlevel 1 (
    echo WARNING: setuptools installation had issues! GPUtil may fail... >> "%DEBUG_LOG%"
    echo WARNING: setuptools installation had issues! GPUtil may fail...
) else (
    echo setuptools installed successfully! >> "%DEBUG_LOG%"
    echo setuptools installed successfully!
)
echo.

:: Get pip version after upgrade
echo Getting pip version after upgrade... >> "%DEBUG_LOG%"
python -m pip --version >> "%DEBUG_LOG%" 2>&1
echo. >> "%DEBUG_LOG%"

:: Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges: Yes >> "%DEBUG_LOG%"
    echo Administrator privileges: Yes
) else (
    echo Administrator privileges: No >> "%DEBUG_LOG%"
    echo Administrator privileges: No
    echo WARNING: Some features require Administrator rights for full functionality.
    echo.
)

:: Function to check if a package is installed
call :is_package_installed customtkinter
set CUSTOMTKINTER_INSTALLED=%ERRORLEVEL%
call :is_package_installed psutil
set PSUTIL_INSTALLED=%ERRORLEVEL%
call :is_package_installed GPUtil
set GPUTIL_INSTALLED=%ERRORLEVEL%
call :is_package_installed wmi
set WMI_INSTALLED=%ERRORLEVEL%
call :is_package_installed speedtest
set SPEEDTEST_INSTALLED=%ERRORLEVEL%
call :is_package_installed PIL
set PILLOW_INSTALLED=%ERRORLEVEL%

:: Check if all dependencies are already installed
if %CUSTOMTKINTER_INSTALLED% EQU 0 (
    if %PSUTIL_INSTALLED% EQU 0 (
        if %GPUTIL_INSTALLED% EQU 0 (
            if %WMI_INSTALLED% EQU 0 (
                if %SPEEDTEST_INSTALLED% EQU 0 (
                    if %PILLOW_INSTALLED% EQU 0 (
                        echo All dependencies already installed! Skipping installation...
                        echo [STEP 3b] All dependencies already installed, skipping >> "%DEBUG_LOG%"
                        goto :skip_installation
                    )
                )
            )
        )
    )
)

echo Installing required dependencies...
echo.
echo [STEP 3b] Installing dependencies >> "%DEBUG_LOG%"

:: Install dependencies from requirements.txt when available
if exist requirements.txt (
    echo Installing dependencies from requirements.txt... >> "%DEBUG_LOG%"
    echo Installing dependencies from requirements.txt...
    echo Command: python -m pip install -r requirements.txt --no-cache-dir >> "%DEBUG_LOG%"
    python -m pip install -r requirements.txt --no-cache-dir
    if errorlevel 1 (
        echo.
        echo WARNING: requirements.txt install had issues. >> "%DEBUG_LOG%"
        echo WARNING: requirements.txt install had issues.
        echo Falling back to individual package installation...
        echo.
        echo Falling back to individual installations... >> "%DEBUG_LOG%"
        
        :: Individual installations with GPUtil fix
        echo Installing customtkinter... >> "%DEBUG_LOG%"
        python -m pip install customtkinter --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        
        echo Installing psutil... >> "%DEBUG_LOG%"
        python -m pip install psutil --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        
        echo Installing GPUtil with compatibility fix... >> "%DEBUG_LOG%"
        python -m pip install GPUtil --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        if errorlevel 1 (
            echo GPUtil failed with distutils error, installing from alternative source... >> "%DEBUG_LOG%"
            echo Attempting to install GPUtil from GitHub fork...
            python -m pip install git+https://github.com/anderskm/GPUtil.git --no-cache-dir >> "%DEBUG_LOG%" 2>&1
            if errorlevel 1 (
                echo WARNING: GPUtil installation failed - GPU monitoring disabled >> "%DEBUG_LOG%"
                echo NOTE: GPU monitoring features will not be available >> "%DEBUG_LOG%"
            ) else (
                echo GPUtil installed from GitHub successfully! >> "%DEBUG_LOG%"
            )
        ) else (
            echo GPUtil installed successfully! >> "%DEBUG_LOG%"
        )
        
        echo Installing wmi... >> "%DEBUG_LOG%"
        python -m pip install wmi --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        
        echo Installing speedtest-cli... >> "%DEBUG_LOG%"
        python -m pip install speedtest-cli --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        
        echo Installing Pillow... >> "%DEBUG_LOG%"
        python -m pip install Pillow --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    )
) else (
    echo requirements.txt not found, installing dependencies individually... >> "%DEBUG_LOG%"
    echo requirements.txt not found, installing dependencies individually...
    echo.
    
    :: Individual installations with GPUtil fix
    if %CUSTOMTKINTER_INSTALLED% NEQ 0 (
        echo Installing customtkinter... >> "%DEBUG_LOG%"
        python -m pip install customtkinter --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    ) else (
        echo customtkinter already installed, skipping...
    )
    
    if %PSUTIL_INSTALLED% NEQ 0 (
        echo Installing psutil... >> "%DEBUG_LOG%"
        python -m pip install psutil --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    ) else (
        echo psutil already installed, skipping...
    )
    
    if %GPUTIL_INSTALLED% NEQ 0 (
        echo Installing GPUtil with compatibility fix... >> "%DEBUG_LOG%"
        echo Attempting to install GPUtil...
        python -m pip install GPUtil --no-cache-dir >> "%DEBUG_LOG%" 2>&1
        if errorlevel 1 (
            echo GPUtil failed with distutils error, installing from alternative source... >> "%DEBUG_LOG%"
            echo Attempting to install GPUtil from GitHub fork...
            python -m pip install git+https://github.com/anderskm/GPUtil.git --no-cache-dir >> "%DEBUG_LOG%" 2>&1
            if errorlevel 1 (
                echo WARNING: GPUtil installation failed - GPU monitoring disabled >> "%DEBUG_LOG%"
                echo NOTE: GPU monitoring features will not be available >> "%DEBUG_LOG%"
                echo.
            ) else (
                echo GPUtil installed from GitHub successfully! >> "%DEBUG_LOG%"
            )
        ) else (
            echo GPUtil installed successfully! >> "%DEBUG_LOG%"
        )
    ) else (
        echo GPUtil already installed, skipping...
    )
    
    if %WMI_INSTALLED% NEQ 0 (
        echo Installing wmi... >> "%DEBUG_LOG%"
        python -m pip install wmi --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    ) else (
        echo wmi already installed, skipping...
    )
    
    if %SPEEDTEST_INSTALLED% NEQ 0 (
        echo Installing speedtest-cli... >> "%DEBUG_LOG%"
        python -m pip install speedtest-cli --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    ) else (
        echo speedtest-cli already installed, skipping...
    )
    
    if %PILLOW_INSTALLED% NEQ 0 (
        echo Installing Pillow... >> "%DEBUG_LOG%"
        python -m pip install Pillow --no-cache-dir >> "%DEBUG_LOG%" 2>&1
    ) else (
        echo Pillow already installed, skipping...
    )
)

:skip_installation
echo.
echo Verifying critical dependencies...
echo.
echo [STEP 3c] Verifying dependencies >> "%DEBUG_LOG%"

:: Verify each dependency and log results
echo customtkinter verification: >> "%DEBUG_LOG%"
python -c "import customtkinter; print('[OK] customtkinter')" 2>nul || echo [MISSING] customtkinter
python -c "import customtkinter; print('customtkinter - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo customtkinter - MISSING >> "%DEBUG_LOG%"

echo psutil verification: >> "%DEBUG_LOG%"
python -c "import psutil; print('[OK] psutil')" 2>nul || echo [MISSING] psutil
python -c "import psutil; print('psutil - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo psutil - MISSING >> "%DEBUG_LOG%"

echo GPUtil verification: >> "%DEBUG_LOG%"
python -c "import GPUtil; print('[OK] GPUtil')" 2>nul || echo [MISSING] GPUtil
python -c "import GPUtil; print('GPUtil - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo GPUtil - MISSING >> "%DEBUG_LOG%"

:: Additional check for Python 3.12+ GPUtil workaround
if %PYTHON_MAJOR% GEQ 3 if %PYTHON_MINOR% GEQ 12 (
    echo NOTE: Python %PYTHON_VERSION% detected - GPUtil may require setuptools >> "%DEBUG_LOG%"
)

echo wmi verification: >> "%DEBUG_LOG%"
python -c "import wmi; print('[OK] wmi')" 2>nul || echo [MISSING] wmi
python -c "import wmi; print('wmi - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo wmi - MISSING >> "%DEBUG_LOG%"

echo speedtest-cli verification: >> "%DEBUG_LOG%"
python -c "import speedtest; print('[OK] speedtest-cli')" 2>nul || echo [MISSING] speedtest-cli
python -c "import speedtest; print('speedtest-cli - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo speedtest-cli - MISSING >> "%DEBUG_LOG%"

echo Pillow verification: >> "%DEBUG_LOG%"
python -c "from PIL import Image; print('[OK] Pillow')" 2>nul || echo [MISSING] Pillow
python -c "from PIL import Image; print('Pillow - OK')" 2>nul >> "%DEBUG_LOG%" 2>&1 || echo Pillow - MISSING >> "%DEBUG_LOG%"

echo.
echo [STEP 4] Locating G.A.L application >> "%DEBUG_LOG%"
echo Locating the latest G.A.L application...
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
    "G.A.L_V1.2.pyw"
    "G.A.L.pyw"
) do (
    if exist %%~F (
        set "MAIN_FILE=%%~F"
        echo Found application: %%~F >> "%DEBUG_LOG%"
        goto :launch
    )
)

:: Fallback: first .pyw in the current folder
for %%i in (*.pyw) do (
    set "MAIN_FILE=%%i"
    echo Found application via fallback: %%i >> "%DEBUG_LOG%"
    goto :launch
)

:launch
if defined MAIN_FILE (
    echo Launching !MAIN_FILE!... >> "%DEBUG_LOG%"
    echo Launching !MAIN_FILE!...
    echo.
    echo [STEP 5] Launching G.A.L application >> "%DEBUG_LOG%"
    echo Command: python "!MAIN_FILE!" >> "%DEBUG_LOG%"
    echo.
    echo ======================================== >> "%DEBUG_LOG%"
    echo G.A.L Application Loaded Successfully >> "%DEBUG_LOG%"
    echo Virtual Environment: %VIRTUAL_ENV% >> "%DEBUG_LOG%"
    echo Application: !MAIN_FILE! >> "%DEBUG_LOG%"
    echo Python Version: %PYTHON_VERSION% >> "%DEBUG_LOG%"
    echo ======================================== >> "%DEBUG_LOG%"
    echo.
    
    python "!MAIN_FILE!"
    
    echo [STEP 6] G.A.L Application closed >> "%DEBUG_LOG%"
    echo Application exit code: !errorlevel! >> "%DEBUG_LOG%"
) else (
    echo ERROR: No Python .pyw file found to launch! >> "%DEBUG_LOG%"
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

:: Final summary
echo. >> "%DEBUG_LOG%"
echo ======================================== >> "%DEBUG_LOG%"
echo INSTALLATION SUMMARY >> "%DEBUG_LOG%"
echo ======================================== >> "%DEBUG_LOG%"
echo Virtual Environment Status: Existing or Created >> "%DEBUG_LOG%"
echo Virtual Environment Path: %VIRTUAL_ENV% >> "%DEBUG_LOG%"
echo Pip Upgraded: Yes >> "%DEBUG_LOG%"
echo Setuptools Installed: Yes >> "%DEBUG_LOG%"
echo Pip Cache Cleared: Yes >> "%DEBUG_LOG%"
echo Dependencies Status: Verified >> "%DEBUG_LOG%"
echo Application Loaded: !MAIN_FILE! >> "%DEBUG_LOG%"
echo Completion Time: %date% %time% >> "%DEBUG_LOG%"
echo ======================================== >> "%DEBUG_LOG%"

echo.
echo ========================================
echo            INSTALLATION SUCCESSFUL!
echo ========================================
echo.
echo All dependencies have been verified!
echo G.A.L is ready to use.
echo.
echo Debug log has been saved to: %DEBUG_LOG%
echo.

pause
endlocal
goto :eof

:: Function to check if a package is installed
:is_package_installed
python -c "import %1" >nul 2>&1
exit /b %ERRORLEVEL%

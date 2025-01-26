@echo off
:: Welcome to the abyss, gamer.
title G.A.L - Enter the System
timeout /t 1 >nul

:: Initialize debug log
set LOG_FILE=GAL_Install_Debug.log
echo [%date% %time%] Starting G.A.L installation... > %LOG_FILE%

:: Set FORCE_INSTALL to 1 to force installation, or 0 for silent mode
set FORCE_INSTALL=0

:: Silent mode: Check if everything is already installed (skipped if FORCE_INSTALL is 1)
if %FORCE_INSTALL% equ 0 (
    echo [%date% %time%] Checking if all dependencies are already installed... >> %LOG_FILE%
    python --version 2>&1 | find "Python 3." >nul
    if %errorlevel% equ 0 (
        pip --version >nul 2>&1
        if %errorlevel% equ 0 (
            set ALL_DEPS_INSTALLED=1
            for /f "tokens=*" %%i in (Requirements.txt) do (
                pip show %%i >nul 2>&1
                if %errorlevel% neq 0 (
                    set ALL_DEPS_INSTALLED=0
                    exit /b
                )
            )
        )
    )

    :: If everything is installed, skip to launching G.A.L.pyw with the custom Silent Mode display
    if defined ALL_DEPS_INSTALLED (
        echo [%date% %time%] All dependencies already installed. Launching G.A.L.pyw... >> %LOG_FILE%

        :: Display "G.A.L Gamers As Legions by xxxnightvoidxxx" for 1 second
        echo G.A.L Gamers As Legions by xxxnightvoidxxx
        timeout /t 2 >nul

        :: Clear the screen
        cls

        :: Display the Borderlands quote
        echo "Nothing is more badass than treating a woman with respect!"
        echo - Borderlands
        timeout /t 3 >nul 
        echo.
        cls
        echo Launching...
        timeout /t 1 >nul

        :: Use PowerShell to hide the console window and launch G.A.L.pyw
        powershell -Command "Start-Process 'pythonw' -ArgumentList 'G.A.L.pyw' -WindowStyle Hidden"
        exit /b
    )
)

:: If anything is missing or FORCE_INSTALL is 1, run the full installation logic
:: Show the console window for installation mode
echo Scanning for Python 3.x...
timeout /t 1 >nul
echo [%date% %time%] Checking for Python 3.x... >> %LOG_FILE%
python --version 2>&1 | find "Python 3." >nul
if %errorlevel% neq 0 (
    echo Python 3.x is MIA. Not cool.
    timeout /t 1 >nul
    echo.
    timeout /t 1 >nul
    echo You need Python to unleash the power. Get it here: https://www.python.org/
    timeout /t 1 >nul
    echo Make sure to check "Add Python to PATH" or face the void.
    timeout /t 1 >nul
    echo.
    timeout /t 1 >nul
    echo Run this script again after you've leveled up.
    timeout /t 1 >nul
    echo [%date% %time%] Python 3.x not found. Installation aborted. >> %LOG_FILE%
    pause
    exit /b 1
)

echo Python 3.x detected. You're not a total noob.
timeout /t 1 >nul
echo [%date% %time%] Python 3.x found. >> %LOG_FILE%

:: Check if pip is installed
echo Probing for pip...
timeout /t 1 >nul
echo [%date% %time%] Checking for pip... >> %LOG_FILE%
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Pip is missing. Did you even install Python properly?
    timeout /t 1 >nul
    echo [%date% %time%] Pip not found. Installation aborted. >> %LOG_FILE%
    pause
    exit /b 1
)

echo Pip is online. Let's roll.
timeout /t 1 >nul
echo [%date% %time%] Pip found. >> %LOG_FILE%

:: Check if running as admin
echo Verifying admin privileges...
timeout /t 1 >nul
echo [%date% %time%] Checking for admin privileges... >> %LOG_FILE%
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo You're not running as admin. Weak.
    timeout /t 1 >nul
    echo Elevating to admin mode. Brace yourself.
    timeout /t 1 >nul
    echo [%date% %time%] Elevating to admin mode... >> %LOG_FILE%
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo Admin privileges confirmed. You're worthy.
timeout /t 1 >nul
echo [%date% %time%] Admin privileges confirmed. >> %LOG_FILE%

:: Upgrade pip
echo Upgrading pip to the latest version... Stay sharp.
timeout /t 1 >nul
echo [%date% %time%] Upgrading pip... >> %LOG_FILE%
python -m pip install --upgrade pip >nul 2>&1
if %errorlevel% neq 0 (
    echo Failed to upgrade pip. Check your connection, scrub.
    timeout /t 1 >nul
    echo [%date% %time%] Failed to upgrade pip. >> %LOG_FILE%
    pause
    exit /b 1
)

echo Pip upgraded. You're getting stronger.
timeout /t 1 >nul
echo [%date% %time%] Pip upgraded. >> %LOG_FILE%

:: Install dependencies from Requirements.txt
echo Loading dependencies from the void...
timeout /t 1 >nul
echo [%date% %time%] Installing dependencies... >> %LOG_FILE%
for /f "tokens=*" %%i in (Requirements.txt) do (
    echo Checking if %%i is already in your arsenal...
    timeout /t 1 >nul
    echo [%date% %time%] Checking for %%i... >> %LOG_FILE%
    pip show %%i >nul 2>&1
    if %errorlevel% neq 0 (
        echo Installing %%i. Sit tight, rookie.
        timeout /t 1 >nul
        echo [%date% %time%] Installing %%i... >> %LOG_FILE%
        pip install %%i >nul 2>&1
        if %errorlevel% neq 0 (
            echo Failed to install %%i. Check your connection, scrub.
            timeout /t 1 >nul
            echo [%date% %time%] Failed to install %%i. >> %LOG_FILE%
            pause
            exit /b 1
        )
        echo %%i installed. You're getting stronger.
        timeout /t 1 >nul
        echo [%date% %time%] %%i installed. >> %LOG_FILE%
    ) else (
        echo %%i is already in your inventory. No duplicates.
        timeout /t 1 >nul
        echo [%date% %time%] %%i already installed. >> %LOG_FILE%
    )
)

echo All dependencies locked and loaded. You're ready.
timeout /t 1 >nul
echo [%date% %time%] All dependencies installed. >> %LOG_FILE%

:: Final message
echo Installation complete. You're now part of the legion.
timeout /t 1 >nul
echo [%date% %time%] Installation complete. >> %LOG_FILE%

:: Open G.A.L.pyw seamlessly
echo Launching G.A.L.pyw... Prepare for greatness.
timeout /t 1 >nul
echo [%date% %time%] Launching G.A.L.pyw... >> %LOG_FILE%
start "" /B pythonw G.A.L.pyw
exit /b
@echo off
title Run Installer Test (Non-Admin)
color 0B

echo.
echo ========================================
echo   Testing Installer (Non-Admin Mode)
echo   This will test the installer logic
echo ========================================
echo.

REM Check if user package exists
if not exist "ECC-IDS-IPS-User-Package" (
    echo [ERROR] User package directory not found!
    pause
    exit /b 1
)

echo [INFO] Changing to user package directory...
cd ECC-IDS-IPS-User-Package

echo [INFO] Current directory: %CD%
echo.

echo [INFO] Running installer (will fail on admin check, but we can see JAR detection)...
echo.

REM Run the installer - it will fail on admin check but we can see if it finds the JAR
call install-security.bat

echo.
echo [INFO] Installer test completed.
echo If you saw "Administrator privileges detected" or "requires administrator privileges",
echo then the JAR file detection is working correctly.
echo.

pause
cd ..

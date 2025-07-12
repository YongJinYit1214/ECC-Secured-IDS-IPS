@echo off
title ECC-IDS-IPS Security System Installer
color 0A

echo.
echo ========================================
echo   ECC-IDS-IPS Security System v1.0.0
echo   Real-Time Network Protection
echo ========================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✓] Administrator privileges detected
) else (
    echo [!] This installer requires administrator privileges
    echo [!] Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo.
echo [INFO] Installing ECC-IDS-IPS Security System...
echo.

REM Create installation directory
set INSTALL_DIR=%ProgramFiles%\ECC-IDS-IPS
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo [✓] Created installation directory: %INSTALL_DIR%
)

REM Copy application files
if exist "ecc-ids-ips.jar" (
    copy "ecc-ids-ips.jar" "%INSTALL_DIR%\ecc-ids-ips.jar" >nul
) else if exist "target\ecc-ids-ips-1.0.0.jar" (
    copy "target\ecc-ids-ips-1.0.0.jar" "%INSTALL_DIR%\ecc-ids-ips.jar" >nul
) else (
    echo [✗] Application JAR file not found
    echo [!] Please ensure ecc-ids-ips.jar is in the current directory
    pause
    exit /b 1
)

if %errorLevel% == 0 (
    echo [✓] Application files copied successfully
) else (
    echo [✗] Failed to copy application files
    pause
    exit /b 1
)

REM Create startup script
echo @echo off > "%INSTALL_DIR%\start-security.bat"
echo title ECC-IDS-IPS Security System >> "%INSTALL_DIR%\start-security.bat"
echo color 0A >> "%INSTALL_DIR%\start-security.bat"
echo echo. >> "%INSTALL_DIR%\start-security.bat"
echo echo ======================================== >> "%INSTALL_DIR%\start-security.bat"
echo echo   ECC-IDS-IPS Security System ACTIVE >> "%INSTALL_DIR%\start-security.bat"
echo echo   Real-Time Network Protection >> "%INSTALL_DIR%\start-security.bat"
echo echo ======================================== >> "%INSTALL_DIR%\start-security.bat"
echo echo. >> "%INSTALL_DIR%\start-security.bat"
echo echo [INFO] Starting security monitoring... >> "%INSTALL_DIR%\start-security.bat"
echo echo [INFO] Dashboard: http://localhost:8080 >> "%INSTALL_DIR%\start-security.bat"
echo echo [INFO] Login: admin / admin123 >> "%INSTALL_DIR%\start-security.bat"
echo echo. >> "%INSTALL_DIR%\start-security.bat"
echo echo [WARNING] Do not close this window! >> "%INSTALL_DIR%\start-security.bat"
echo echo [WARNING] Closing will stop network protection! >> "%INSTALL_DIR%\start-security.bat"
echo echo. >> "%INSTALL_DIR%\start-security.bat"
echo java -Xmx1g -jar "%INSTALL_DIR%\ecc-ids-ips.jar" >> "%INSTALL_DIR%\start-security.bat"
echo pause >> "%INSTALL_DIR%\start-security.bat"

echo [✓] Startup script created

REM Create desktop shortcut
set DESKTOP=%USERPROFILE%\Desktop
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\CreateShortcut.vbs"
echo sLinkFile = "%DESKTOP%\ECC Security Monitor.lnk" >> "%TEMP%\CreateShortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\CreateShortcut.vbs"
echo oLink.TargetPath = "%INSTALL_DIR%\start-security.bat" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.WorkingDirectory = "%INSTALL_DIR%" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Description = "ECC-IDS-IPS Security System - Real-Time Network Protection" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.IconLocation = "%SystemRoot%\System32\shell32.dll,48" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Save >> "%TEMP%\CreateShortcut.vbs"
cscript "%TEMP%\CreateShortcut.vbs" >nul
del "%TEMP%\CreateShortcut.vbs"
echo [✓] Desktop shortcut created

REM Create Windows service (optional)
echo.
echo [OPTION] Install as Windows Service for automatic startup?
echo [Y] Yes - Start automatically with Windows
echo [N] No - Manual startup only
echo.
set /p SERVICE_CHOICE="Enter choice (Y/N): "

if /i "%SERVICE_CHOICE%"=="Y" (
    echo.
    echo [INFO] Installing Windows Service...
    
    REM Create service wrapper script
    echo @echo off > "%INSTALL_DIR%\service-wrapper.bat"
    echo cd /d "%INSTALL_DIR%" >> "%INSTALL_DIR%\service-wrapper.bat"
    echo java -Xmx1g -jar ecc-ids-ips.jar >> "%INSTALL_DIR%\service-wrapper.bat"
    
    REM Install service using sc command
    sc create "ECC-IDS-IPS" binPath= "\"%INSTALL_DIR%\service-wrapper.bat\"" DisplayName= "ECC-IDS-IPS Security System" start= auto >nul
    if %errorLevel% == 0 (
        echo [✓] Windows Service installed successfully
        echo [INFO] Service will start automatically with Windows
        
        REM Start the service
        sc start "ECC-IDS-IPS" >nul
        if %errorLevel% == 0 (
            echo [✓] Service started successfully
        ) else (
            echo [!] Service installed but failed to start
            echo [!] You can start it manually from Services.msc
        )
    ) else (
        echo [✗] Failed to install Windows Service
        echo [INFO] You can still use the desktop shortcut for manual startup
    )
)

REM Create uninstaller
echo @echo off > "%INSTALL_DIR%\uninstall.bat"
echo title ECC-IDS-IPS Security System Uninstaller >> "%INSTALL_DIR%\uninstall.bat"
echo echo Uninstalling ECC-IDS-IPS Security System... >> "%INSTALL_DIR%\uninstall.bat"
echo sc stop "ECC-IDS-IPS" ^>nul 2^>^&1 >> "%INSTALL_DIR%\uninstall.bat"
echo sc delete "ECC-IDS-IPS" ^>nul 2^>^&1 >> "%INSTALL_DIR%\uninstall.bat"
echo del "%DESKTOP%\ECC Security Monitor.lnk" ^>nul 2^>^&1 >> "%INSTALL_DIR%\uninstall.bat"
echo cd /d "%ProgramFiles%" >> "%INSTALL_DIR%\uninstall.bat"
echo rmdir /s /q "ECC-IDS-IPS" >> "%INSTALL_DIR%\uninstall.bat"
echo echo Uninstallation complete. >> "%INSTALL_DIR%\uninstall.bat"
echo pause >> "%INSTALL_DIR%\uninstall.bat"

echo [✓] Uninstaller created

echo.
echo ========================================
echo   INSTALLATION COMPLETE!
echo ========================================
echo.
echo [✓] ECC-IDS-IPS Security System installed successfully
echo [✓] Desktop shortcut: "ECC Security Monitor"
echo [✓] Installation directory: %INSTALL_DIR%
echo.
echo NEXT STEPS:
echo 1. Double-click "ECC Security Monitor" on your desktop
echo 2. Wait for the system to start (may take 30-60 seconds)
echo 3. Open browser to: http://localhost:8080
echo 4. Login with: admin / admin123
echo.
echo FEATURES:
echo • Real-time network monitoring and protection
echo • Automatic blocking of malicious IPs
echo • Professional security dashboard
echo • Zero false positive detection rules
echo • Military-grade ECC encryption
echo.
echo WARNING: Do not close the security monitor window!
echo Closing it will stop network protection.
echo.
echo For support, check the documentation in the installation folder.
echo.
pause

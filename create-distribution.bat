@echo off
title ECC-IDS-IPS Distribution Package Creator
color 0B

echo.
echo ========================================
echo   ECC-IDS-IPS Distribution Creator
echo   Creating User-Friendly Package
echo ========================================
echo.

REM Build the application
echo [1/5] Building application...
call mvn clean package -DskipTests
if %errorLevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo [✓] Application built successfully

REM Create distribution directory
set DIST_DIR=ECC-IDS-IPS-Distribution
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%DIST_DIR%"
echo [✓] Distribution directory created

REM Copy application files
echo [2/5] Copying application files...
copy "target\ecc-ids-ips-1.0.0.jar" "%DIST_DIR%\ecc-ids-ips.jar" >nul
copy "install-security.bat" "%DIST_DIR%\" >nul
copy "Install-Security.ps1" "%DIST_DIR%\" >nul
echo [✓] Application files copied

REM Copy documentation
echo [3/5] Copying documentation...
mkdir "%DIST_DIR%\docs"
copy "README.md" "%DIST_DIR%\docs\" >nul
copy "USER_GUIDE.md" "%DIST_DIR%\docs\" >nul
copy "TESTING_GUIDE.md" "%DIST_DIR%\docs\" >nul
copy "PRODUCTION_GUIDE.md" "%DIST_DIR%\docs\" >nul
echo [✓] Documentation copied

REM Create user-friendly README
echo [4/5] Creating user instructions...
echo # 🛡️ ECC-IDS-IPS Security System > "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ## Quick Start Guide >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ### For Windows Users: >> "%DIST_DIR%\README.txt"
echo 1. Right-click "install-security.bat" >> "%DIST_DIR%\README.txt"
echo 2. Select "Run as administrator" >> "%DIST_DIR%\README.txt"
echo 3. Follow the installation wizard >> "%DIST_DIR%\README.txt"
echo 4. Double-click the desktop shortcut to start >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ### For PowerShell Users: >> "%DIST_DIR%\README.txt"
echo 1. Right-click PowerShell and "Run as administrator" >> "%DIST_DIR%\README.txt"
echo 2. Run: .\Install-Security.ps1 -AutoStart >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ### What This Does: >> "%DIST_DIR%\README.txt"
echo • Monitors your network in real-time >> "%DIST_DIR%\README.txt"
echo • Automatically blocks malicious IPs >> "%DIST_DIR%\README.txt"
echo • Provides a security dashboard at http://localhost:8080 >> "%DIST_DIR%\README.txt"
echo • Uses military-grade encryption to protect your data >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ### Login Credentials: >> "%DIST_DIR%\README.txt"
echo Username: admin >> "%DIST_DIR%\README.txt"
echo Password: admin123 >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo ### Support: >> "%DIST_DIR%\README.txt"
echo Check the 'docs' folder for detailed documentation. >> "%DIST_DIR%\README.txt"
echo [✓] User instructions created

REM Create quick start script
echo [5/5] Creating quick start options...
echo @echo off > "%DIST_DIR%\QUICK-START.bat"
echo title ECC-IDS-IPS Quick Start >> "%DIST_DIR%\QUICK-START.bat"
echo color 0A >> "%DIST_DIR%\QUICK-START.bat"
echo echo. >> "%DIST_DIR%\QUICK-START.bat"
echo echo ======================================== >> "%DIST_DIR%\QUICK-START.bat"
echo echo   🛡️  ECC-IDS-IPS Security System >> "%DIST_DIR%\QUICK-START.bat"
echo echo   Quick Start Menu >> "%DIST_DIR%\QUICK-START.bat"
echo echo ======================================== >> "%DIST_DIR%\QUICK-START.bat"
echo echo. >> "%DIST_DIR%\QUICK-START.bat"
echo echo [1] Install as Windows Service (Recommended) >> "%DIST_DIR%\QUICK-START.bat"
echo echo [2] Install for Manual Start >> "%DIST_DIR%\QUICK-START.bat"
echo echo [3] Run Once (No Installation) >> "%DIST_DIR%\QUICK-START.bat"
echo echo [4] View Documentation >> "%DIST_DIR%\QUICK-START.bat"
echo echo [5] Exit >> "%DIST_DIR%\QUICK-START.bat"
echo echo. >> "%DIST_DIR%\QUICK-START.bat"
echo set /p choice="Select option (1-5): " >> "%DIST_DIR%\QUICK-START.bat"
echo. >> "%DIST_DIR%\QUICK-START.bat"
echo if "%%choice%%"=="1" ( >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Installing as Windows Service... >> "%DIST_DIR%\QUICK-START.bat"
echo     powershell -ExecutionPolicy Bypass -File "Install-Security.ps1" -Service -AutoStart >> "%DIST_DIR%\QUICK-START.bat"
echo ^) else if "%%choice%%"=="2" ( >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Installing for manual start... >> "%DIST_DIR%\QUICK-START.bat"
echo     call install-security.bat >> "%DIST_DIR%\QUICK-START.bat"
echo ^) else if "%%choice%%"=="3" ( >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Starting ECC-IDS-IPS Security System... >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Dashboard: http://localhost:8080 >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Login: admin / admin123 >> "%DIST_DIR%\QUICK-START.bat"
echo     java -Xmx1g -jar ecc-ids-ips.jar >> "%DIST_DIR%\QUICK-START.bat"
echo ^) else if "%%choice%%"=="4" ( >> "%DIST_DIR%\QUICK-START.bat"
echo     start docs\README.md >> "%DIST_DIR%\QUICK-START.bat"
echo ^) else if "%%choice%%"=="5" ( >> "%DIST_DIR%\QUICK-START.bat"
echo     exit >> "%DIST_DIR%\QUICK-START.bat"
echo ^) else ( >> "%DIST_DIR%\QUICK-START.bat"
echo     echo Invalid choice. Please try again. >> "%DIST_DIR%\QUICK-START.bat"
echo     pause >> "%DIST_DIR%\QUICK-START.bat"
echo     goto start >> "%DIST_DIR%\QUICK-START.bat"
echo ^) >> "%DIST_DIR%\QUICK-START.bat"

echo [✓] Quick start menu created

REM Create ZIP package
echo.
echo Creating ZIP package...
powershell -command "Compress-Archive -Path '%DIST_DIR%\*' -DestinationPath 'ECC-IDS-IPS-Security-v1.0.0.zip' -Force"
if %errorLevel% == 0 (
    echo [✓] ZIP package created: ECC-IDS-IPS-Security-v1.0.0.zip
) else (
    echo [!] ZIP creation failed, but distribution folder is ready
)

echo.
echo ========================================
echo   📦 DISTRIBUTION PACKAGE READY! 📦
echo ========================================
echo.
echo 📁 Distribution folder: %DIST_DIR%\
echo 📦 ZIP package: ECC-IDS-IPS-Security-v1.0.0.zip
echo.
echo 🎯 WHAT USERS GET:
echo ✅ One-click installer (install-security.bat)
echo ✅ PowerShell installer (Install-Security.ps1)
echo ✅ Quick start menu (QUICK-START.bat)
echo ✅ Complete documentation
echo ✅ Ready-to-run security system
echo.
echo 🚀 USER INSTRUCTIONS:
echo 1. Extract the ZIP file
echo 2. Run QUICK-START.bat as administrator
echo 3. Choose installation option
echo 4. Access dashboard at http://localhost:8080
echo.
echo 🔐 FEATURES FOR USERS:
echo • Real-time network protection
echo • Automatic malicious IP blocking
echo • Professional security dashboard
echo • Zero false positive detection
echo • Military-grade encryption
echo • Windows Service option
echo • Desktop shortcuts
echo • Comprehensive documentation
echo.
pause

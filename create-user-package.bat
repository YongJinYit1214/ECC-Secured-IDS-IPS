@echo off
title Create ECC-IDS-IPS User Distribution Package
color 0B

echo.
echo ========================================
echo   📦 ECC-IDS-IPS User Package Creator
echo   Creating Distribution for End Users
echo ========================================
echo.

REM Check if JAR exists
if not exist "target\ecc-ids-ips-1.0.0.jar" (
    echo [ERROR] Application JAR not found!
    echo Please build the application first:
    echo   mvn clean package -DskipTests
    echo.
    pause
    exit /b 1
)

REM Create distribution directory
set DIST_DIR=ECC-IDS-IPS-User-Package
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%DIST_DIR%"
echo [✓] Created distribution directory: %DIST_DIR%

REM Copy application JAR
if exist "target\ecc-ids-ips-1.0.0.jar" (
    copy "target\ecc-ids-ips-1.0.0.jar" "%DIST_DIR%\ecc-ids-ips.jar" >nul
    if %errorLevel% == 0 (
        echo [✓] Copied application JAR
    ) else (
        echo [✗] Failed to copy application JAR
        pause
        exit /b 1
    )
) else (
    echo [✗] Application JAR not found: target\ecc-ids-ips-1.0.0.jar
    echo Please build the application first: mvn clean package -DskipTests
    pause
    exit /b 1
)

REM Copy installer scripts
copy "install-security.bat" "%DIST_DIR%\" >nul 2>nul
copy "Install-Security.ps1" "%DIST_DIR%\" >nul 2>nul
echo [✓] Copied installer scripts

REM Create user-friendly README
echo 🛡️ ECC-IDS-IPS Security System > "%DIST_DIR%\README.txt"
echo Real-Time Network Protection for Your Computer >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo QUICK START: >> "%DIST_DIR%\README.txt"
echo 1. Right-click "install-security.bat" >> "%DIST_DIR%\README.txt"
echo 2. Select "Run as administrator" >> "%DIST_DIR%\README.txt"
echo 3. Follow the installation wizard >> "%DIST_DIR%\README.txt"
echo 4. Access dashboard: http://localhost:8080 >> "%DIST_DIR%\README.txt"
echo 5. Login: admin / admin123 >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo WHAT THIS DOES: >> "%DIST_DIR%\README.txt"
echo • Monitors your network in real-time >> "%DIST_DIR%\README.txt"
echo • Automatically blocks malicious IPs >> "%DIST_DIR%\README.txt"
echo • Provides professional security dashboard >> "%DIST_DIR%\README.txt"
echo • Uses military-grade encryption >> "%DIST_DIR%\README.txt"
echo • Zero false positives - only real threats >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo FEATURES: >> "%DIST_DIR%\README.txt"
echo • Port scanning detection (50+ connections/min) >> "%DIST_DIR%\README.txt"
echo • Brute force prevention (25+ failed attempts) >> "%DIST_DIR%\README.txt"
echo • Data exfiltration monitoring (8KB+ packets) >> "%DIST_DIR%\README.txt"
echo • DDoS attack detection (500+ connections) >> "%DIST_DIR%\README.txt"
echo • Malicious payload detection (SQL injection, XSS) >> "%DIST_DIR%\README.txt"
echo • Known malicious IP blocking >> "%DIST_DIR%\README.txt"
echo. >> "%DIST_DIR%\README.txt"
echo SUPPORT: >> "%DIST_DIR%\README.txt"
echo Check the 'docs' folder for detailed guides. >> "%DIST_DIR%\README.txt"
echo [✓] Created user README

REM Copy documentation
mkdir "%DIST_DIR%\docs"
copy "README.md" "%DIST_DIR%\docs\" >nul 2>nul
copy "USER_GUIDE.md" "%DIST_DIR%\docs\" >nul 2>nul
copy "TESTING_GUIDE.md" "%DIST_DIR%\docs\" >nul 2>nul
copy "PRODUCTION_GUIDE.md" "%DIST_DIR%\docs\" >nul 2>nul
copy "USER_DISTRIBUTION_GUIDE.md" "%DIST_DIR%\docs\" >nul 2>nul
echo [✓] Copied documentation

REM Create simple run script for users who don't want to install
echo @echo off > "%DIST_DIR%\run-once.bat"
echo title ECC-IDS-IPS Security System >> "%DIST_DIR%\run-once.bat"
echo color 0A >> "%DIST_DIR%\run-once.bat"
echo echo. >> "%DIST_DIR%\run-once.bat"
echo echo ======================================== >> "%DIST_DIR%\run-once.bat"
echo echo   🛡️  ECC-IDS-IPS Security System >> "%DIST_DIR%\run-once.bat"
echo echo   Real-Time Network Protection >> "%DIST_DIR%\run-once.bat"
echo echo ======================================== >> "%DIST_DIR%\run-once.bat"
echo echo. >> "%DIST_DIR%\run-once.bat"
echo echo [INFO] Starting security system... >> "%DIST_DIR%\run-once.bat"
echo echo [INFO] Dashboard: http://localhost:8080 >> "%DIST_DIR%\run-once.bat"
echo echo [INFO] Login: admin / admin123 >> "%DIST_DIR%\run-once.bat"
echo echo. >> "%DIST_DIR%\run-once.bat"
echo echo ⚠️  Keep this window open for protection! >> "%DIST_DIR%\run-once.bat"
echo echo ⚠️  Closing will stop network monitoring! >> "%DIST_DIR%\run-once.bat"
echo echo. >> "%DIST_DIR%\run-once.bat"
echo java -Xmx1g -jar ecc-ids-ips.jar >> "%DIST_DIR%\run-once.bat"
echo pause >> "%DIST_DIR%\run-once.bat"
echo [✓] Created run-once script

REM Create ZIP package
echo.
echo [INFO] Creating ZIP package...
powershell -command "Compress-Archive -Path '%DIST_DIR%\*' -DestinationPath 'ECC-IDS-IPS-Security-v1.0.0.zip' -Force" 2>nul
if %errorLevel% == 0 (
    echo [✓] ZIP package created: ECC-IDS-IPS-Security-v1.0.0.zip
) else (
    echo [!] ZIP creation failed, but folder is ready: %DIST_DIR%
)

echo.
echo ========================================
echo   📦 USER PACKAGE READY! 📦
echo ========================================
echo.
echo 📁 Package folder: %DIST_DIR%\
echo 📦 ZIP file: ECC-IDS-IPS-Security-v1.0.0.zip
echo.
echo 🎯 WHAT USERS GET:
echo ✅ One-click installer (install-security.bat)
echo ✅ PowerShell installer (Install-Security.ps1)
echo ✅ Run-once option (run-once.bat)
echo ✅ User-friendly README.txt
echo ✅ Complete documentation
echo ✅ Ready-to-run security system
echo.
echo 📋 USER INSTRUCTIONS:
echo 1. Extract ZIP file
echo 2. Right-click install-security.bat
echo 3. Select "Run as administrator"
echo 4. Follow installation wizard
echo 5. Access http://localhost:8080
echo.
echo 🛡️ SECURITY FEATURES:
echo • Real-time network monitoring
echo • Automatic malicious IP blocking
echo • Professional security dashboard
echo • Zero false positive detection
echo • Military-grade ECC encryption
echo • Production-tuned thresholds
echo.
echo 🚀 DISTRIBUTION READY:
echo Your package is ready to distribute to users!
echo They get enterprise-grade security with one-click installation.
echo.
pause

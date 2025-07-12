# ECC-IDS-IPS Security System PowerShell Installer
# Requires PowerShell 5.0+ and Administrator privileges

param(
    [switch]$AutoStart,
    [switch]$Service,
    [string]$InstallPath = "$env:ProgramFiles\ECC-IDS-IPS"
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script requires administrator privileges" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host @"
========================================
  ECC-IDS-IPS Security System v1.0.0
  Real-Time Network Protection Installer
========================================
"@ -ForegroundColor Cyan

Write-Host "🔧 Installing ECC-IDS-IPS Security System..." -ForegroundColor Green

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "✅ Created installation directory: $InstallPath" -ForegroundColor Green
}

# Check for Java
try {
    $javaVersion = java -version 2>&1 | Select-String "version"
    if ($javaVersion -match '"(\d+)\.') {
        $majorVersion = [int]$matches[1]
        if ($majorVersion -ge 17) {
            Write-Host "✅ Java $majorVersion detected" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Java $majorVersion detected (Java 17+ recommended)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "❌ Java not found. Please install Java 17+ from https://adoptopenjdk.net/" -ForegroundColor Red
    Read-Host "Press Enter to continue anyway"
}

# Copy application files
if (Test-Path "ecc-ids-ips.jar") {
    Copy-Item "ecc-ids-ips.jar" "$InstallPath\ecc-ids-ips.jar" -Force
    Write-Host "✅ Application files copied successfully" -ForegroundColor Green
} elseif (Test-Path "target\ecc-ids-ips-1.0.0.jar") {
    Copy-Item "target\ecc-ids-ips-1.0.0.jar" "$InstallPath\ecc-ids-ips.jar" -Force
    Write-Host "✅ Application files copied successfully" -ForegroundColor Green
} else {
    Write-Host "❌ Application JAR file not found" -ForegroundColor Red
    Write-Host "Please ensure ecc-ids-ips.jar is in the current directory" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Create startup script
$startupScript = @"
@echo off
title ECC-IDS-IPS Security System - ACTIVE
color 0A
echo.
echo ========================================
echo   🛡️  ECC-IDS-IPS Security ACTIVE  🛡️
echo   Real-Time Network Protection
echo ========================================
echo.
echo [INFO] Starting security monitoring...
echo [INFO] Dashboard: http://localhost:8080
echo [INFO] Login: admin / admin123
echo.
echo ⚠️  IMPORTANT: Keep this window open!
echo ⚠️  Closing will stop network protection!
echo.
echo 🔍 Monitoring for:
echo   • Port scanning attacks
echo   • Brute force attempts  
echo   • Malicious payloads
echo   • Data exfiltration
echo   • DDoS attacks
echo.
java -Xmx1g -jar "$InstallPath\ecc-ids-ips.jar"
pause
"@

$startupScript | Out-File "$InstallPath\start-security.bat" -Encoding ASCII
Write-Host "✅ Startup script created" -ForegroundColor Green

# Create PowerShell startup script
$psStartupScript = @"
# ECC-IDS-IPS Security System Launcher
Write-Host "🛡️  Starting ECC-IDS-IPS Security System..." -ForegroundColor Cyan
Write-Host "Dashboard: http://localhost:8080" -ForegroundColor Yellow
Write-Host "Login: admin / admin123" -ForegroundColor Yellow
Write-Host ""
Write-Host "⚠️  Keep this window open for continuous protection!" -ForegroundColor Red
Write-Host ""

# Start the application
Set-Location "$InstallPath"
java -Xmx1g -jar ecc-ids-ips.jar
"@

$psStartupScript | Out-File "$InstallPath\Start-Security.ps1" -Encoding UTF8
Write-Host "✅ PowerShell startup script created" -ForegroundColor Green

# Create desktop shortcut
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\🛡️ ECC Security Monitor.lnk")
$Shortcut.TargetPath = "$InstallPath\start-security.bat"
$Shortcut.WorkingDirectory = $InstallPath
$Shortcut.Description = "ECC-IDS-IPS Security System - Real-Time Network Protection"
$Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,48"
$Shortcut.Save()
Write-Host "✅ Desktop shortcut created" -ForegroundColor Green

# Create Start Menu shortcut
$StartMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$StartMenuShortcut = $WshShell.CreateShortcut("$StartMenuPath\ECC Security Monitor.lnk")
$StartMenuShortcut.TargetPath = "$InstallPath\start-security.bat"
$StartMenuShortcut.WorkingDirectory = $InstallPath
$StartMenuShortcut.Description = "ECC-IDS-IPS Security System"
$StartMenuShortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,48"
$StartMenuShortcut.Save()
Write-Host "✅ Start Menu shortcut created" -ForegroundColor Green

# Create configuration file for user settings
$configContent = @"
# ECC-IDS-IPS User Configuration
# Edit these settings to customize your security system

# Network Interface (auto-detect by default)
sensor.interface=auto

# Detection Sensitivity (production, high, medium, low)
detection.sensitivity=production

# Auto-block malicious IPs (true/false)
prevention.auto-block=true

# Block duration in seconds (3600 = 1 hour)
prevention.block-duration=3600

# Dashboard auto-open (true/false)
dashboard.auto-open=true

# Notification settings
notifications.enabled=true
notifications.sound=true
"@

$configContent | Out-File "$InstallPath\user-config.properties" -Encoding UTF8
Write-Host "✅ User configuration file created" -ForegroundColor Green

# Install as Windows Service (optional)
if ($Service) {
    Write-Host "🔧 Installing Windows Service..." -ForegroundColor Yellow
    
    # Create service wrapper
    $serviceWrapper = @"
@echo off
cd /d "$InstallPath"
java -Xmx1g -jar ecc-ids-ips.jar
"@
    $serviceWrapper | Out-File "$InstallPath\service-wrapper.bat" -Encoding ASCII
    
    try {
        $serviceName = "ECC-IDS-IPS"
        $serviceDisplayName = "ECC-IDS-IPS Security System"
        $servicePath = "`"$InstallPath\service-wrapper.bat`""
        
        # Remove existing service if it exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $serviceName | Out-Null
        }
        
        # Install new service
        & sc.exe create $serviceName binPath= $servicePath DisplayName= $serviceDisplayName start= auto | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Windows Service installed successfully" -ForegroundColor Green
            Write-Host "🔄 Starting service..." -ForegroundColor Yellow
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($?) {
                Write-Host "✅ Service started successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Service installed but failed to start automatically" -ForegroundColor Yellow
            }
        } else {
            Write-Host "❌ Failed to install Windows Service" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Error installing service: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Create uninstaller
$uninstaller = @"
# ECC-IDS-IPS Security System Uninstaller
Write-Host "🗑️  Uninstalling ECC-IDS-IPS Security System..." -ForegroundColor Yellow

# Stop and remove service
try {
    Stop-Service -Name "ECC-IDS-IPS" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "ECC-IDS-IPS" | Out-Null
    Write-Host "✅ Service removed" -ForegroundColor Green
} catch {
    Write-Host "ℹ️  No service to remove" -ForegroundColor Gray
}

# Remove shortcuts
Remove-Item "$env:USERPROFILE\Desktop\🛡️ ECC Security Monitor.lnk" -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\ECC Security Monitor.lnk" -ErrorAction SilentlyContinue
Write-Host "✅ Shortcuts removed" -ForegroundColor Green

# Remove installation directory
Remove-Item "$InstallPath" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "✅ Installation files removed" -ForegroundColor Green

Write-Host "✅ Uninstallation complete!" -ForegroundColor Green
Read-Host "Press Enter to exit"
"@

$uninstaller | Out-File "$InstallPath\Uninstall.ps1" -Encoding UTF8
Write-Host "✅ Uninstaller created" -ForegroundColor Green

# Auto-start if requested
if ($AutoStart) {
    Write-Host "🚀 Starting ECC-IDS-IPS Security System..." -ForegroundColor Cyan
    Start-Process "$InstallPath\start-security.bat"
    Start-Sleep 3
    
    # Auto-open dashboard
    Write-Host "🌐 Opening security dashboard..." -ForegroundColor Cyan
    Start-Process "http://localhost:8080"
}

Write-Host @"

========================================
   ✅ INSTALLATION COMPLETE! ✅
========================================

🛡️  ECC-IDS-IPS Security System is ready!

📍 Installation Location: $InstallPath
🖥️  Desktop Shortcut: 🛡️ ECC Security Monitor
📱 Start Menu: ECC Security Monitor

🚀 QUICK START:
1. Double-click the desktop shortcut
2. Wait 30-60 seconds for startup
3. Open: http://localhost:8080
4. Login: admin / admin123

🔒 SECURITY FEATURES:
• Real-time network monitoring
• Automatic malicious IP blocking  
• Zero false positive detection
• Professional security dashboard
• Military-grade ECC encryption

⚠️  IMPORTANT:
Keep the security monitor window open!
Closing it stops network protection.

📚 Documentation: $InstallPath\docs\
🗑️  Uninstall: Run $InstallPath\Uninstall.ps1

"@ -ForegroundColor Green

if (!$AutoStart) {
    $startNow = Read-Host "Start ECC-IDS-IPS Security now? (Y/N)"
    if ($startNow -eq 'Y' -or $startNow -eq 'y') {
        Write-Host "🚀 Starting security system..." -ForegroundColor Cyan
        Start-Process "$InstallPath\start-security.bat"
        Start-Sleep 3
        Start-Process "http://localhost:8080"
    }
}

Write-Host "Installation completed successfully! 🎉" -ForegroundColor Green

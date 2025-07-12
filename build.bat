@echo off
REM ECC-Secured IDS/IPS Build Script for Windows
REM This script builds and optionally runs the IDS/IPS system

setlocal enabledelayedexpansion

REM Colors (limited in Windows CMD)
set "INFO=[INFO]"
set "SUCCESS=[SUCCESS]"
set "WARNING=[WARNING]"
set "ERROR=[ERROR]"

REM Function to check prerequisites
:check_prerequisites
echo %INFO% Checking prerequisites...

REM Check Java
java -version >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Java is not installed. Please install Java 17 or higher.
    exit /b 1
)

for /f "tokens=3" %%i in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VERSION=%%i
    set JAVA_VERSION=!JAVA_VERSION:"=!
)
echo %SUCCESS% Java !JAVA_VERSION! found

REM Check Maven
mvn -version >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Maven is not installed. Please install Maven 3.6 or higher.
    exit /b 1
)

for /f "tokens=3" %%i in ('mvn -version 2^>^&1 ^| findstr /i "Apache Maven"') do (
    set MVN_VERSION=%%i
)
echo %SUCCESS% Maven !MVN_VERSION! found
goto :eof

REM Function to clean previous builds
:clean_build
echo %INFO% Cleaning previous builds...
mvn clean >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Clean failed
    exit /b 1
)
echo %SUCCESS% Clean completed
goto :eof

REM Function to compile the application
:compile_app
echo %INFO% Compiling application...
mvn compile >build.log 2>&1
if errorlevel 1 (
    echo %ERROR% Compilation failed. Check build.log for details.
    exit /b 1
)
echo %SUCCESS% Compilation completed
goto :eof

REM Function to run tests
:run_tests
echo %INFO% Running tests...
mvn test >test.log 2>&1
if errorlevel 1 (
    echo %WARNING% Some tests failed. Check test.log for details.
    exit /b 1
)
echo %SUCCESS% All tests passed
goto :eof

REM Function to package the application
:package_app
echo %INFO% Packaging application...
mvn package -DskipTests >package.log 2>&1
if errorlevel 1 (
    echo %ERROR% Packaging failed. Check package.log for details.
    exit /b 1
)
echo %SUCCESS% Packaging completed
goto :eof

REM Function to create directories
:create_directories
echo %INFO% Creating necessary directories...
if not exist logs mkdir logs
if not exist config mkdir config
echo %SUCCESS% Directories created
goto :eof

REM Function to copy configuration files
:copy_configs
echo %INFO% Copying configuration files...
if not exist config\application.yml (
    copy src\main\resources\application.yml config\ >nul
    echo %SUCCESS% Configuration copied to config\application.yml
    echo %WARNING% Please review and customize config\application.yml before running
) else (
    echo %WARNING% Configuration file already exists in config\
)
goto :eof

REM Function to display usage
:show_usage
echo Usage: %0 [OPTIONS]
echo.
echo Options:
echo   -h, --help     Show this help message
echo   -c, --clean    Clean build artifacts
echo   -t, --test     Run tests
echo   -r, --run      Run the application after building
echo   -s, --skip-tests  Skip running tests during build
echo.
echo Examples:
echo   %0              # Build the application
echo   %0 --test       # Build and run tests
echo   %0 --run        # Build and run the application
echo   %0 --clean --test --run  # Clean, build, test, and run
goto :eof

REM Function to run the application
:run_app
echo %INFO% Starting ECC-Secured IDS/IPS...
echo %WARNING% Press Ctrl+C to stop the application

set JAR_FILE=target\ecc-ids-ips-1.0.0.jar
if not exist "%JAR_FILE%" (
    echo %ERROR% JAR file not found: %JAR_FILE%
    echo %ERROR% Please build the application first
    exit /b 1
)

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo %WARNING% Not running as administrator. Network packet capture may not work.
    echo %WARNING% Run as administrator for full functionality or enable simulation mode.
)

java -jar "%JAR_FILE%" --spring.config.location=file:./config/application.yml
goto :eof

REM Main build function
:main_build
set skip_tests=%1

call :check_prerequisites
if errorlevel 1 exit /b 1

call :clean_build
if errorlevel 1 exit /b 1

call :compile_app
if errorlevel 1 exit /b 1

if not "%skip_tests%"=="skip-tests" (
    call :run_tests
)

call :package_app
if errorlevel 1 exit /b 1

call :create_directories
call :copy_configs

echo %SUCCESS% Build completed successfully!
echo %INFO% JAR file: target\ecc-ids-ips-1.0.0.jar
echo %INFO% Configuration: config\application.yml
echo %INFO% Logs will be written to: logs\
echo.
echo %INFO% To run the application:
echo %INFO%   %0 --run
echo %INFO%   or
echo %INFO%   java -jar target\ecc-ids-ips-1.0.0.jar
goto :eof

REM Parse command line arguments
set CLEAN=false
set TEST=false
set RUN=false
set SKIP_TESTS=false

:parse_args
if "%1"=="" goto :done_parsing
if "%1"=="-h" goto :show_help
if "%1"=="--help" goto :show_help
if "%1"=="-c" set CLEAN=true
if "%1"=="--clean" set CLEAN=true
if "%1"=="-t" set TEST=true
if "%1"=="--test" set TEST=true
if "%1"=="-r" set RUN=true
if "%1"=="--run" set RUN=true
if "%1"=="-s" set SKIP_TESTS=true
if "%1"=="--skip-tests" set SKIP_TESTS=true
shift
goto :parse_args

:show_help
call :show_usage
exit /b 0

:done_parsing

REM Main execution
echo %INFO% ECC-Secured IDS/IPS Build Script
echo %INFO% ================================

if "%CLEAN%"=="true" (
    call :clean_build
    if errorlevel 1 exit /b 1
)

if "%SKIP_TESTS%"=="true" (
    call :main_build skip-tests
) else (
    call :main_build
)
if errorlevel 1 exit /b 1

if "%TEST%"=="true" (
    call :run_tests
)

if "%RUN%"=="true" (
    echo.
    call :run_app
)

endlocal

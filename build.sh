#!/bin/bash

# ECC-Secured IDS/IPS Build Script
# This script builds and optionally runs the IDS/IPS system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Java
    if ! command -v java &> /dev/null; then
        print_error "Java is not installed. Please install Java 17 or higher."
        exit 1
    fi
    
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
    if [ "$JAVA_VERSION" -lt 17 ]; then
        print_error "Java 17 or higher is required. Current version: $JAVA_VERSION"
        exit 1
    fi
    print_success "Java $JAVA_VERSION found"
    
    # Check Maven
    if ! command -v mvn &> /dev/null; then
        print_error "Maven is not installed. Please install Maven 3.6 or higher."
        exit 1
    fi
    
    MVN_VERSION=$(mvn -version | head -n 1 | cut -d' ' -f3)
    print_success "Maven $MVN_VERSION found"
}

# Function to clean previous builds
clean_build() {
    print_status "Cleaning previous builds..."
    mvn clean > /dev/null 2>&1
    print_success "Clean completed"
}

# Function to compile the application
compile_app() {
    print_status "Compiling application..."
    if mvn compile > build.log 2>&1; then
        print_success "Compilation completed"
    else
        print_error "Compilation failed. Check build.log for details."
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    if mvn test > test.log 2>&1; then
        print_success "All tests passed"
    else
        print_warning "Some tests failed. Check test.log for details."
        return 1
    fi
}

# Function to package the application
package_app() {
    print_status "Packaging application..."
    if mvn package -DskipTests > package.log 2>&1; then
        print_success "Packaging completed"
    else
        print_error "Packaging failed. Check package.log for details."
        exit 1
    fi
}

# Function to create directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p logs
    mkdir -p config
    print_success "Directories created"
}

# Function to copy configuration files
copy_configs() {
    print_status "Copying configuration files..."
    if [ ! -f config/application.yml ]; then
        cp src/main/resources/application.yml config/
        print_success "Configuration copied to config/application.yml"
        print_warning "Please review and customize config/application.yml before running"
    else
        print_warning "Configuration file already exists in config/"
    fi
}

# Function to display usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -c, --clean    Clean build artifacts"
    echo "  -t, --test     Run tests"
    echo "  -r, --run      Run the application after building"
    echo "  -s, --skip-tests  Skip running tests during build"
    echo ""
    echo "Examples:"
    echo "  $0              # Build the application"
    echo "  $0 --test       # Build and run tests"
    echo "  $0 --run        # Build and run the application"
    echo "  $0 --clean --test --run  # Clean, build, test, and run"
}

# Function to run the application
run_app() {
    print_status "Starting ECC-Secured IDS/IPS..."
    print_warning "Press Ctrl+C to stop the application"
    
    JAR_FILE="target/ecc-ids-ips-1.0.0.jar"
    if [ ! -f "$JAR_FILE" ]; then
        print_error "JAR file not found: $JAR_FILE"
        print_error "Please build the application first"
        exit 1
    fi
    
    # Check if running as root (for packet capture)
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root. Network packet capture may not work."
        print_warning "Run with sudo for full functionality or enable simulation mode."
    fi
    
    java -jar "$JAR_FILE" --spring.config.location=file:./config/application.yml
}

# Main build function
main_build() {
    local skip_tests=false
    
    if [ "$1" = "skip-tests" ]; then
        skip_tests=true
    fi
    
    check_prerequisites
    clean_build
    compile_app
    
    if [ "$skip_tests" = false ]; then
        run_tests
    fi
    
    package_app
    create_directories
    copy_configs
    
    print_success "Build completed successfully!"
    print_status "JAR file: target/ecc-ids-ips-1.0.0.jar"
    print_status "Configuration: config/application.yml"
    print_status "Logs will be written to: logs/"
    echo ""
    print_status "To run the application:"
    print_status "  ./build.sh --run"
    print_status "  or"
    print_status "  java -jar target/ecc-ids-ips-1.0.0.jar"
}

# Parse command line arguments
CLEAN=false
TEST=false
RUN=false
SKIP_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -t|--test)
            TEST=true
            shift
            ;;
        -r|--run)
            RUN=true
            shift
            ;;
        -s|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
print_status "ECC-Secured IDS/IPS Build Script"
print_status "================================"

if [ "$CLEAN" = true ]; then
    clean_build
fi

if [ "$SKIP_TESTS" = true ]; then
    main_build "skip-tests"
else
    main_build
fi

if [ "$TEST" = true ]; then
    run_tests
fi

if [ "$RUN" = true ]; then
    echo ""
    run_app
fi

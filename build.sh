#!/bin/bash

# PDF Scrubber Build Script
# Comprehensive build system for all platforms

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE=${BUILD_TYPE:-Release}
BUILD_DIR=${BUILD_DIR:-build}
INSTALL_PREFIX=${INSTALL_PREFIX:-/usr/local}
NUM_CORES=${NUM_CORES:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}

echo -e "${BLUE}PDF Scrubber Build System${NC}"
echo -e "${BLUE}=========================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake is required but not installed"
        exit 1
    fi
    
    CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
    print_status "CMake version: $CMAKE_VERSION"
    
    # Check compiler
    if command -v g++ &> /dev/null; then
        GCC_VERSION=$(g++ --version | head -n1)
        print_status "Compiler: $GCC_VERSION"
    elif command -v clang++ &> /dev/null; then
        CLANG_VERSION=$(clang++ --version | head -n1)
        print_status "Compiler: $CLANG_VERSION"
    else
        print_error "No C++ compiler found (g++ or clang++ required)"
        exit 1
    fi
    
    # Check OpenSSL
    if pkg-config --exists openssl; then
        OPENSSL_VERSION=$(pkg-config --modversion openssl)
        print_status "OpenSSL version: $OPENSSL_VERSION"
    else
        print_warning "OpenSSL development libraries may not be installed"
    fi
    
    # Check zlib
    if pkg-config --exists zlib; then
        ZLIB_VERSION=$(pkg-config --modversion zlib)
        print_status "zlib version: $ZLIB_VERSION"
    else
        print_warning "zlib development libraries may not be installed"
    fi
}

# Install dependencies based on platform
install_dependencies() {
    print_status "Installing dependencies..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian
            sudo apt-get update
            sudo apt-get install -y build-essential cmake pkg-config libssl-dev zlib1g-dev
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y cmake pkg-config openssl-devel zlib-devel
        elif command -v dnf &> /dev/null; then
            # Fedora
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y cmake pkg-config openssl-devel zlib-devel
        else
            print_warning "Unknown Linux distribution - please install dependencies manually"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install cmake openssl zlib pkg-config
        else
            print_warning "Homebrew not found - please install dependencies manually"
        fi
    else
        print_warning "Unknown platform - please install dependencies manually"
    fi
}

# Configure build
configure_build() {
    print_status "Configuring build (Type: $BUILD_TYPE)..."
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    # Configure with CMake
    cmake .. \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    
    cd ..
}

# Build project
build_project() {
    print_status "Building project with $NUM_CORES cores..."
    
    cd "$BUILD_DIR"
    cmake --build . --config "$BUILD_TYPE" --parallel "$NUM_CORES"
    cd ..
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    cd "$BUILD_DIR"
    ctest --output-on-failure --parallel "$NUM_CORES"
    cd ..
}

# Install project
install_project() {
    print_status "Installing project to $INSTALL_PREFIX..."
    
    cd "$BUILD_DIR"
    if [[ "$INSTALL_PREFIX" == "/usr/local" ]] || [[ "$INSTALL_PREFIX" == "/usr" ]]; then
        sudo cmake --install .
    else
        cmake --install .
    fi
    cd ..
}

# Package project
package_project() {
    print_status "Creating distribution packages..."
    
    cd "$BUILD_DIR"
    cpack
    cd ..
    
    print_status "Packages created in $BUILD_DIR:"
    ls -la "$BUILD_DIR"/*.tar.gz "$BUILD_DIR"/*.zip "$BUILD_DIR"/*.deb "$BUILD_DIR"/*.rpm 2>/dev/null || true
}

# Clean build
clean_build() {
    print_status "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
}

# Main execution
main() {
    case "${1:-all}" in
        "deps")
            check_requirements
            install_dependencies
            ;;
        "configure")
            check_requirements
            configure_build
            ;;
        "build")
            check_requirements
            configure_build
            build_project
            ;;
        "test")
            check_requirements
            configure_build
            build_project
            run_tests
            ;;
        "install")
            check_requirements
            configure_build
            build_project
            run_tests
            install_project
            ;;
        "package")
            check_requirements
            configure_build
            build_project
            run_tests
            package_project
            ;;
        "clean")
            clean_build
            ;;
        "all"|*)
            check_requirements
            configure_build
            build_project
            run_tests
            print_status "Build completed successfully!"
            echo ""
            echo -e "${GREEN}Executables built:${NC}"
            echo "  - $BUILD_DIR/bin/pdfscrubber (main application)"
            echo "  - $BUILD_DIR/bin/pdfforensic (forensic analysis)"
            echo "  - $BUILD_DIR/test_suite (test runner)"
            echo ""
            echo -e "${GREEN}Next steps:${NC}"
            echo "  - Run './build.sh install' to install system-wide"
            echo "  - Run './build.sh package' to create distribution packages"
            echo "  - Run '$BUILD_DIR/bin/pdfscrubber --help' for usage"
            ;;
    esac
}

# Show help
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "PDF Scrubber Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all       - Complete build process (default)"
    echo "  deps      - Install system dependencies"
    echo "  configure - Configure build system"
    echo "  build     - Build project only"
    echo "  test      - Build and run tests"
    echo "  install   - Build, test, and install"
    echo "  package   - Create distribution packages"
    echo "  clean     - Clean build directory"
    echo ""
    echo "Environment variables:"
    echo "  BUILD_TYPE      - Debug or Release (default: Release)"
    echo "  BUILD_DIR       - Build directory (default: build)"
    echo "  INSTALL_PREFIX  - Installation prefix (default: /usr/local)"
    echo "  NUM_CORES       - Number of build cores (default: auto-detect)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Full build and test"
    echo "  $0 deps               # Install dependencies only"
    echo "  BUILD_TYPE=Debug $0   # Debug build"
    echo "  $0 package            # Create distribution packages"
    exit 0
fi

# Execute main function
main "$@"
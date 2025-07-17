#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/protoc"
SRC_DIR="$SCRIPT_DIR/protoc"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect platform and architecture
detect_platform() {
    local platform=$(uname -s)
    local arch=$(uname -m)
    
    log_info "Detected platform: $platform ($arch)"
    
    case $platform in
        Linux)
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="$ID"
                VERSION="$VERSION_ID"
                log_info "Distribution: $DISTRO $VERSION"
            else
                DISTRO="unknown"
                VERSION="unknown"
            fi
            ;;
        Darwin)
            DISTRO="macos"
            VERSION=$(sw_vers -productVersion)
            log_info "macOS version: $VERSION"
            ;;
        *)
            log_error "Unsupported platform: $platform"
            exit 1
            ;;
    esac
    
    # Set optimization flags based on architecture
    case $arch in
        aarch64|arm64)
            ARCH_FLAGS="-march=armv8-a+crc+crypto"
            log_info "ARM64 optimizations enabled"
            ;;
        x86_64)
            ARCH_FLAGS="-march=x86-64 -mtune=generic"
            log_info "x86_64 optimizations enabled"
            ;;
        *)
            ARCH_FLAGS=""
            log_warning "No specific optimizations for architecture: $arch"
            ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies based on distribution
install_dependencies() {
    log_info "Installing build dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            if ! command_exists apt-get; then
                log_error "apt-get not found on $DISTRO system"
                exit 1
            fi
            
            log_info "Updating package list..."
            sudo apt-get update -qq
            
            log_info "Installing required packages..."
            sudo apt-get install -y \
                build-essential \
                pkg-config \
                libnl-3-dev \
                libnl-genl-3-dev \
                libnl-route-3-dev \
                gcc \
                make
            ;;
            
        fedora|centos|rhel)
            if command_exists dnf; then
                PKG_MGR="dnf"
            elif command_exists yum; then
                PKG_MGR="yum"
            else
                log_error "No package manager found (dnf/yum)"
                exit 1
            fi
            
            log_info "Installing required packages with $PKG_MGR..."
            sudo $PKG_MGR install -y \
                gcc \
                make \
                pkg-config \
                libnl3-devel \
                kernel-headers
            ;;
            
        arch)
            if ! command_exists pacman; then
                log_error "pacman not found on Arch system"
                exit 1
            fi
            
            log_info "Installing required packages..."
            sudo pacman -S --needed --noconfirm \
                base-devel \
                pkg-config \
                libnl
            ;;
            
        alpine)
            if ! command_exists apk; then
                log_error "apk not found on Alpine system"
                exit 1
            fi
            
            log_info "Installing required packages..."
            sudo apk add --no-cache \
                build-base \
                pkgconfig \
                libnl3-dev \
                linux-headers
            ;;
            
        macos)
            if ! command_exists brew; then
                log_error "Homebrew not found. Please install Homebrew first."
                exit 1
            fi
            
            log_info "Installing required packages with Homebrew..."
            brew install pkg-config libnl
            ;;
            
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_info "Please install the following packages manually:"
            log_info "  - build-essential/gcc/make"
            log_info "  - pkg-config"
            log_info "  - libnl-3-dev (or libnl3-devel)"
            log_info "  - libnl-genl-3-dev"
            exit 1
            ;;
    esac
    
    log_success "Dependencies installed successfully"
}

# Verify dependencies
verify_dependencies() {
    log_info "Verifying build dependencies..."
    
    local missing_deps=()
    
    # Check for compiler
    if ! command_exists gcc; then
        missing_deps+=("gcc")
    fi
    
    # Check for make
    if ! command_exists make; then
        missing_deps+=("make")
    fi
    
    # Check for pkg-config
    if ! command_exists pkg-config; then
        missing_deps+=("pkg-config")
    fi
    
    # Check for libnl headers
    if ! pkg-config --exists libnl-3.0; then
        missing_deps+=("libnl-3.0")
    fi
    
    if ! pkg-config --exists libnl-genl-3.0; then
        missing_deps+=("libnl-genl-3.0")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    log_success "All dependencies verified"
    return 0
}

# Build the C programs
build_programs() {
    log_info "Building C programs..."
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    # Get compiler flags
    local nl_cflags=$(pkg-config --cflags libnl-3.0 libnl-genl-3.0)
    local nl_libs=$(pkg-config --libs libnl-3.0 libnl-genl-3.0)
    
    # Set compiler flags
    local cflags="-std=c99 -Wall -Wextra -O2 $ARCH_FLAGS $nl_cflags"
    local ldflags="$nl_libs"
    
    log_info "Compiler flags: $cflags"
    log_info "Linker flags: $ldflags"
    
    # Build wifi-monitor-check
    log_info "Building wifi-monitor-check..."
    gcc $cflags -o "$BUILD_DIR/wifi-monitor-check" "$SRC_DIR/wifi-monitor-check.c" $ldflags
    
    if [ $? -eq 0 ]; then
        log_success "wifi-monitor-check built successfully"
    else
        log_error "Failed to build wifi-monitor-check"
        exit 1
    fi
    
    # Build wifi-monitor-setup
    log_info "Building wifi-monitor-setup..."
    gcc $cflags -o "$BUILD_DIR/wifi-monitor-setup" "$SRC_DIR/wifi-monitor-setup.c" $ldflags
    
    if [ $? -eq 0 ]; then
        log_success "wifi-monitor-setup built successfully"
    else
        log_error "Failed to build wifi-monitor-setup"
        exit 1
    fi
    
    # Make executables
    chmod +x "$BUILD_DIR/wifi-monitor-check"
    chmod +x "$BUILD_DIR/wifi-monitor-setup"
}

# Test the built programs
test_programs() {
    log_info "Testing built programs..."
    
    # Test wifi-monitor-check (should run without errors)
    log_info "Testing wifi-monitor-check..."
    if "$BUILD_DIR/wifi-monitor-check" >/dev/null 2>&1; then
        log_success "wifi-monitor-check test passed"
    else
        log_warning "wifi-monitor-check test failed (may need root privileges or wireless hardware)"
    fi
    
    # Test wifi-monitor-setup help
    log_info "Testing wifi-monitor-setup argument parsing..."
    if "$BUILD_DIR/wifi-monitor-setup" 2>&1 | grep -q "Usage:"; then
        log_success "wifi-monitor-setup argument parsing works"
    else
        log_warning "wifi-monitor-setup may have issues"
    fi
}

# Create installation symlinks
create_symlinks() {
    log_info "Creating symlinks in project root..."
    
    # Remove existing symlinks if they exist
    [ -L "$SCRIPT_DIR/wifi-monitor-check" ] && rm "$SCRIPT_DIR/wifi-monitor-check"
    [ -L "$SCRIPT_DIR/wifi-monitor-setup" ] && rm "$SCRIPT_DIR/wifi-monitor-setup"
    
    # Create new symlinks
    ln -s "build/protoc/wifi-monitor-check" "$SCRIPT_DIR/wifi-monitor-check"
    ln -s "build/protoc/wifi-monitor-setup" "$SCRIPT_DIR/wifi-monitor-setup"
    
    log_success "Symlinks created in project root"
}

# Clean build directory
clean() {
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    rm -f "$SCRIPT_DIR/wifi-monitor-check"
    rm -f "$SCRIPT_DIR/wifi-monitor-setup"
    log_success "Build directory cleaned"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install-deps    Install system dependencies"
    echo "  --clean          Clean build directory"
    echo "  --no-test        Skip program testing"
    echo "  --help           Show this help message"
    echo ""
    echo "By default, this script will:"
    echo "  1. Detect platform and architecture"
    echo "  2. Verify dependencies"
    echo "  3. Build the programs"
    echo "  4. Test the programs"
    echo "  5. Create symlinks"
}

# Main execution
main() {
    local install_deps=false
    local run_tests=true
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install-deps)
                install_deps=true
                shift
                ;;
            --clean)
                clean
                exit 0
                ;;
            --no-test)
                run_tests=false
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting WATR protocol C program build"
    
    # Detect platform
    detect_platform
    
    # Install dependencies if requested
    if [ "$install_deps" = true ]; then
        install_dependencies
    fi
    
    # Verify dependencies
    if ! verify_dependencies; then
        log_error "Dependencies not satisfied. Run with --install-deps to install them."
        exit 1
    fi
    
    # Build programs
    build_programs
    
    # Test programs
    if [ "$run_tests" = true ]; then
        test_programs
    fi
    
    # Create symlinks
    create_symlinks
    
    log_success "Build completed successfully!"
    log_info "Executables available at:"
    log_info "  - $BUILD_DIR/wifi-monitor-check"
    log_info "  - $BUILD_DIR/wifi-monitor-setup"
    log_info "  - $SCRIPT_DIR/wifi-monitor-check (symlink)"
    log_info "  - $SCRIPT_DIR/wifi-monitor-setup (symlink)"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
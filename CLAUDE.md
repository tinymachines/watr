# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WATR is a custom protocol development project that combines C/C++ high-performance components with Python bindings and Scapy integration for packet crafting and analysis.

## Architecture

- **C++ Core (`src/`, `include/`)**: High-performance protocol implementation
- **Python Bindings (`src/bindings.cpp`)**: pybind11 bridge between C++ and Python
- **Python Package (`python/watr/`)**: Python API and Scapy integration
- **Scapy Submodule (`scapy/`)**: Git submodule for packet manipulation
- **Tests (`tests/`)**: Test suite for both C++ and Python components

## Development Setup

### Environment Setup
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Update submodules
git submodule update --init --recursive
```

### Building the Project
```bash
# Create build directory
mkdir -p build && cd build

# Configure with cmake
cmake ..

# Build C++ components and Python bindings
make -j$(nproc)

# Install Python package in development mode
cd .. && pip install -e .
```

### Running Tests
```bash
# Python tests
pytest tests/ -v --cov=watr

# C++ tests (if available)
cd build && ctest

# Scapy integration tests
python -m pytest tests/test_scapy_integration.py
```

## Key Components

### Protocol Class (`watr::Protocol`)
Core C++ class for packet operations:
- `craft_packet()`: Create packets from data
- `parse_packet()`: Parse incoming packets
- `set_header_field()`/`get_header_field()`: Header manipulation

### Scapy Integration (`python/watr/scapy_layers.py`)
Custom Scapy layers:
- `WATRHeader`: Protocol header definition
- `WATRPayload`: Payload handling
- Layer binding for automatic packet assembly

### Python API (`python/watr/__init__.py`)
High-level Python interface exposing C++ functionality through pybind11.

## Development Guidelines

### Adding New Protocol Features
1. Implement C++ functionality in `src/protocol.cpp`
2. Add corresponding header declarations in `include/watr/protocol.h`
3. Expose to Python via `src/bindings.cpp`
4. Create Scapy layer definitions in `python/watr/scapy_layers.py`
5. Add comprehensive tests

### Scapy Submodule Management
```bash
# Update scapy to latest version
cd scapy && git pull origin main && cd ..
git add scapy && git commit -m "Update scapy submodule"

# Initialize scapy submodule in fresh clone
git submodule update --init --recursive
```

### Testing Strategy
- Unit tests for C++ components using Google Test (if added)
- Python unit tests with pytest
- Integration tests for C++/Python bindings
- Scapy layer validation tests
- Performance benchmarks for packet processing

## Common Commands

```bash
# Full development cycle
source venv/bin/activate
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd ..
pip install -e .
pytest tests/ -v

# Quick Python-only development
source venv/bin/activate
python -c "import watr; print(watr.__version__)"

# Interactive Scapy with WATR layers
source venv/bin/activate
python -c "from scapy.all import *; from watr.scapy_layers import *"
```

## ARM64/Raspberry Pi 4 Deployment

WATR is optimized for deployment on Raspberry Pi 4 running Debian Bookworm (ARM64).

### Quick Deployment
```bash
# Deploy to a Raspberry Pi
./deploy_to_rpi.sh <hostname>

# Example: Deploy to tm11.local
./deploy_to_rpi.sh tm11.local
```

### Platform-Specific Notes
- Target platform: ARM64/aarch64 architecture
- OS: Debian Bookworm or compatible
- C++ optimizations: `-march=armv8-a+crc+crypto`
- Installation directory: `/opt/watr`
- No cross-compilation needed - builds natively on target

### Distribution Build
```bash
# Create distribution package
./build_dist.sh

# Deploy manually
scp dist/watr-dist-*.tar.gz user@rpi:/tmp/
ssh user@rpi
tar -xzf /tmp/watr-dist-*.tar.gz
cd watr-dist-*/scripts
./setup.sh
```
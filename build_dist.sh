#!/bin/bash
# Build distribution package for ARM64/Raspberry Pi 4 deployment

set -e

DIST_NAME="watr-dist-$(date +%Y%m%d-%H%M%S)"
DIST_DIR="dist/$DIST_NAME"

echo "Building WATR distribution package..."

# Clean previous builds
rm -rf dist build

# Create distribution directory structure
mkdir -p "$DIST_DIR"/{src,scripts,config}

# Copy source files (excluding venv and build artifacts)
echo "Copying source files..."
rsync -av --exclude='venv/' --exclude='build/' --exclude='dist/' \
    --exclude='*.pyc' --exclude='__pycache__/' --exclude='.git/' \
    --exclude='*.so' --exclude='*.o' \
    ./ "$DIST_DIR/src/"

# Create setup script for target system
cat > "$DIST_DIR/scripts/setup.sh" << 'EOF'
#!/bin/bash
# Setup script for WATR on Raspberry Pi 4 (ARM64)

set -e

echo "Setting up WATR on Raspberry Pi 4..."

# Update system packages
echo "Updating system packages..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    python3-dev \
    python3-venv \
    python3-pip \
    git \
    libpcap-dev

# Create virtual environment
echo "Creating Python virtual environment..."
cd /opt/watr
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Build C++ components
echo "Building C++ components..."
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# Install Python package
echo "Installing WATR Python package..."
pip install -e .

echo "WATR setup complete!"
echo "Activate environment with: source /opt/watr/venv/bin/activate"
EOF

# Create deployment script
cat > "$DIST_DIR/scripts/deploy.sh" << 'EOF'
#!/bin/bash
# Deploy WATR to target system

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target-host>"
    exit 1
fi

TARGET_HOST=$1
TARGET_DIR="/opt/watr"

echo "Deploying WATR to $TARGET_HOST..."

# Create target directory
ssh "$TARGET_HOST" "sudo mkdir -p $TARGET_DIR && sudo chown \$USER:pi $TARGET_DIR"

# Copy source files
echo "Copying files to $TARGET_HOST..."
rsync -avz --exclude='dist/' ../src/ "$TARGET_HOST:$TARGET_DIR/"

# Run setup script
echo "Running setup on $TARGET_HOST..."
ssh "$TARGET_HOST" "cd $TARGET_DIR && bash scripts/setup.sh"

echo "Deployment complete!"
EOF

# Create systemd service file
cat > "$DIST_DIR/config/watr.service" << 'EOF'
[Unit]
Description=WATR Protocol Service
After=network.target

[Service]
Type=simple
User=pi
Group=pi
WorkingDirectory=/opt/watr
Environment="PATH=/opt/watr/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/watr/venv/bin/python -m watr.service
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Make scripts executable
chmod +x "$DIST_DIR/scripts/"*.sh

# Create distribution README
cat > "$DIST_DIR/README.md" << 'EOF'
# WATR Distribution Package

This package contains everything needed to deploy WATR on a Raspberry Pi 4 running Debian Bookworm.

## Deployment

1. Run the deployment script from the scripts directory:
   ```bash
   cd scripts
   ./deploy.sh <target-hostname>
   ```

2. Or manually copy and setup:
   ```bash
   scp -r ../src/* user@target:/opt/watr/
   ssh user@target
   cd /opt/watr
   bash scripts/setup.sh
   ```

## Post-Installation

- Activate the virtual environment: `source /opt/watr/venv/bin/activate`
- Run tests: `pytest tests/`
- Start service: `sudo systemctl start watr`

## Requirements

- Raspberry Pi 4 with ARM64 architecture
- Debian Bookworm or compatible OS
- Python 3.9+
- Network connectivity for package installation
EOF

# Create tarball
echo "Creating distribution archive..."
cd dist
tar -czf "$DIST_NAME.tar.gz" "$DIST_NAME"

echo "Distribution package created: dist/$DIST_NAME.tar.gz"
echo "Ready for deployment to Raspberry Pi 4!"
#!/bin/bash
# Deploy WATR directly to Raspberry Pi 4

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target-host>"
    exit 1
fi

TARGET_HOST=$1
TARGET_DIR="/opt/watr"

echo "Deploying WATR to $TARGET_HOST..."

# Create target directory
ssh "$TARGET_HOST" "sudo mkdir -p $TARGET_DIR && sudo chown \$USER:\$USER $TARGET_DIR"

# Copy source files (excluding unnecessary files)
echo "Copying source files to $TARGET_HOST..."
rsync -avz --exclude='venv/' --exclude='build/' --exclude='dist/' \
    --exclude='*.pyc' --exclude='__pycache__/' --exclude='.git/' \
    --exclude='*.so' --exclude='*.o' --exclude='scapy/.git' \
    ./ "$TARGET_HOST:$TARGET_DIR/"

# Create and run setup script on target
echo "Setting up WATR on $TARGET_HOST..."
ssh "$TARGET_HOST" << 'EOF'
cd /opt/watr

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
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements-rpi.txt

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

# Initialize scapy submodule
echo "Initializing scapy submodule..."
git submodule update --init --recursive

echo "WATR setup complete!"
echo "To activate: source /opt/watr/venv/bin/activate"
EOF

echo "Deployment complete! Testing installation..."

# Test the installation
ssh "$TARGET_HOST" << 'EOF'
cd /opt/watr
source venv/bin/activate
python -c "import watr; print(f'WATR {watr.__version__} installed successfully!')"
python -c "import scapy; print(f'Scapy {scapy.__version__} available')"
EOF
#!/bin/bash

# Anti-DDoS Build Script
# ======================

set -e

echo "============================================="
echo "  Building Anti-DDoS Protection System"
echo "============================================="
echo ""

# Clean previous build
if [ -d "build" ]; then
    echo "Cleaning previous build..."
    rm -rf build
fi

if [ -d "bin" ]; then
    rm -rf bin
fi

# Create directories
mkdir -p build bin

# Configure
echo "Configuring..."
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo "Building..."
make -j$(nproc 2>/dev/null || echo 4)

# Copy binaries to bin/
echo "Copying binaries to bin/..."
if [ -f "antiddos-cli" ]; then
    cp antiddos-cli ../bin/
fi
if [ -f "antiddos-daemon" ]; then
    cp antiddos-daemon ../bin/
fi
if [ -f "xdp-cli" ]; then
    cp xdp-cli ../bin/
fi
if [ -f "xdp-loader" ]; then
    cp xdp-loader ../bin/
fi

cd ..

echo ""
echo "============================================="
echo "  Build Complete!"
echo "============================================="
echo ""
echo "Binaries available in bin/:"
ls -la bin/
echo ""
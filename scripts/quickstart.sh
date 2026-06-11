#!/bin/bash

# Anti-DDoS Quick Start Script
# ============================

echo "============================================="
echo "  Anti-DDoS Quick Start"
echo "============================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    OS="unknown"
fi

echo "Detected OS: $OS"
echo ""

# Build
echo "Building project..."
if [ ! -d "build" ]; then
    mkdir build
fi

cd build
cmake .. 2>/dev/null || { echo "Error: CMake failed"; exit 1; }
make -j$(nproc 2>/dev/null || echo 4) 2>/dev/null || { echo "Error: Build failed"; exit 1; }
cd ..

echo "Build successful!"
echo ""

# Run CLI
echo "Starting Anti-DDoS CLI..."
echo ""
./build/antiddos-cli help
#!/bin/bash

. ./0_circuit_to_build.sh

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

echo '****COMPILING CIRCUIT****'
start=`date +%s`
set -x
circom "$CIRCUIT_PATH" --r1cs --wasm --sym --c --wat --output "$BUILD_DIR"
end=`date +%s`
{ set +x; } 2>/dev/null
echo "DONE ($((end-start))s)"
echo
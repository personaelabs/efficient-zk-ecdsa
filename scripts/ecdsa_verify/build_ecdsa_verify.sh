CIRCUITS_DIR=../../circuits
PHASE1=$CIRCUITS_DIR/pot18_final.ptau
BUILD_DIR=../../build/ecdsa_verify
CIRCUIT_NAME=ecdsa_verify

if [ -f "$PHASE1" ]; then
    echo "Found Phase 1 ptau file"
else
    echo "No Phase 1 ptau file found. Exiting..."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

echo "****COMPILING CIRCUIT****"
start=`date +%s`
set -x
circom "$CIRCUITS_DIR/$CIRCUIT_NAME".circom --r1cs --wasm --sym --c --wat --output "$BUILD_DIR"
{ set +x; } 2>/dev/null
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING ZKEY 0****"
start=`date +%s`
npx snarkjs groth16 setup "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$BUILD_DIR"/"$CIRCUIT_NAME"_0.zkey
end=`date +%s`
echo "DONE ($((end-start))s)"
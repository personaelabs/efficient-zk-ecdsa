#!/bin/bash

. ./0_circuit_to_build.sh

echo "****EXPORTING VKEY****"
start=`date +%s`
set -x
../node_modules/.bin/snarkjs zkey export verificationkey "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/vkey.json
end=`date +%s`
{ set +x; } 2>/dev/null
echo "DONE ($((end-start))s)"
echo
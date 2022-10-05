CIRCUIT_NAME="pubkey_from_secret_message"
CIRCUIT_PATH="../circuits/$CIRCUIT_NAME.circom"
SAMPLE_INPUT="sample_input.json"
BUILD_DIR="../build/$CIRCUIT_NAME"
R1CS_FILE="$BUILD_DIR/$CIRCUIT_NAME.r1cs"
PARTIAL_ZKEYS="$BUILD_DIR"/partial_zkeys
PHASE1=../circuits/pot21_final.ptau
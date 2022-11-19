const prove = async (wasmFile, zKeyFile) => {
  console.log("Proving...");
  console.time("fullProve");

  const fullProof = await snarkjs.groth16.fullProve(
    sampleInput,
    wasmFile,
    zKeyFile
  );

  console.log({ fullProof });
  console.timeEnd("fullProve");
};

const verify = async () => {
  await prove(
    "https://d2q52de7b4rwg.cloudfront.net/ecdsa_verify.wasm",
    "https://d2q52de7b4rwg.cloudfront.net/ecdsa_verify.zkey"
  );
};

const verifyPubKeyToAddr = async () => {
  await prove(
    "https://d2q52de7b4rwg.cloudfront.net/ecdsa_verify_pubkey_to_addr.wasm",
    "https://d2q52de7b4rwg.cloudfront.net/ecdsa_verify_pubkey_to_addr.zkey"
  );
};

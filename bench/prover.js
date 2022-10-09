const wasmFile = `https://storage.googleapis.com/prover_jp/ecdsa_verify.wasm`;
const zKeyFile = "https://storage.googleapis.com/prover_jp/ecdsa_verify.zkey";

// const wasmFile = "zk-ecdsa.s3.ap-northeast-1.amazonaws.com/ecdsa_verify.wasm";
// const wasmFile = "zk-ecdsa.s3.ap-northeast-1.amazonaws.com/ecdsa_verify.zkey";

const verify = async () => {
  console.log("Proving....");

  console.time("fullProve");

  const fullProof = await snarkjs.groth16
    .fullProve(sampleInput, wasmFile, zKeyFile)
    .catch(err => {
      console.error(err);
    });
  console.log(fullProof);

  console.timeEnd("fullProve");

  console.log("Done....");
};

const snarkJs = require("snarkjs");
const { hashPersonalMessage, ecsign } = require("@ethereumjs/util");
const { SECP256K1_N } = require("../utils/config");
const elliptic = require("elliptic");
const ec = new elliptic.ec("secp256k1");
const BN = require("bn.js");
const { splitToRegisters, registersToHex } = require("../utils/utils");
const fs = require("fs");

const privKey = BigInt(
  "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
);

const ZKEY_PATH =
  "build/ecdsa_verify_no_precompute/build_ecdsa_verify_no_precompute.zkey";
const VKEY_PATH = "build/ecdsa_verify_no_precompute/verification_key.json";

const verify = async (proof, publicSignals) => {
  const vKey = JSON.parse(fs.readFileSync(VKEY_PATH));
  const result = await snarkJs.groth16.verify(vKey, publicSignals, proof);
  if (result) {
    console.log("Proof verified!");
  } else {
    console.log("Proof verification failed");
  }
};

const prove = async () => {
  if (!fs.existsSync(ZKEY_PATH)) {
    console.log(
      "zkey not found. Please run `yarn build:ecdsa_verify_no_precompute` first"
    );
    return;
  }

  console.time("Full proof generation");

  const msgHash = hashPersonalMessage(Buffer.from("hello world"));

  const pubKey = ec.keyFromPrivate(privKey.toString(16)).getPublic();

  const { v, r, s } = ecsign(msgHash, privKey);

  const isYOdd = (v - BigInt(27)) % BigInt(2);
  const rPoint = ec.keyFromPublic(
    ec.curve.pointFromX(new BN(r), isYOdd).encode("hex"),
    "hex"
  );

  // Get the group element: -(m * r^−1 * G)
  const rInv = new BN(r).invm(SECP256K1_N);

  // w = -(r^-1 * msg)
  const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N);
  // U = -(w * G) = -(r^-1 * msg * G)
  const U = ec.curve.g.mul(w);

  // T = r^-1 * R
  const T = rPoint.getPublic().mul(rInv);

  const input = {
    T: [splitToRegisters(T.x), splitToRegisters(T.y)],
    U: [splitToRegisters(U.x), splitToRegisters(U.y)],
    s: [splitToRegisters(s.toString("hex"))]
  };

  console.log("Proving...");
  const { publicSignals, proof } = await snarkJs.groth16.fullProve(
    input,
    "build/ecdsa_verify_no_precompute/build_ecdsa_verify_no_precompute_js/build_ecdsa_verify_no_precompute.wasm",
    ZKEY_PATH
  );

  const outputPubkeyX = registersToHex(publicSignals.slice(0, 4).reverse());
  const outputPubkeyY = registersToHex(publicSignals.slice(4, 8).reverse());
  const outputPubKey = `${outputPubkeyX}${outputPubkeyY}`;

  if (`04${outputPubKey}` === pubKey.encode("hex")) {
    console.log("Success!");
    console.timeEnd("Full proof generation");
  } else {
    console.log("Output public key doesn't match expected public key");
  }

  // Now, verify the proof
  await verify(proof, publicSignals);

  process.exit(0);
};

prove();

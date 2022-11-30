const snarkJs = require("snarkjs");
const {
  hashPersonalMessage,
  ecsign,
  publicToAddress
} = require("@ethereumjs/util");
const { SECP256K1_N } = require("../utils/config");
const elliptic = require("elliptic");
const ec = new elliptic.ec("secp256k1");
const BN = require("bn.js");
const { splitToRegisters, registersToHex } = require("../utils/utils");
const fs = require("fs");
const { getPointPreComputes } = require("../utils/point-cache");

const privKey = BigInt(
  "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
);

const ZKEY_PATH =
  "build/ecdsa_verify_pubkey_to_addr/build_ecdsa_verify_pubkey_to_addr.zkey";
const VKEY_PATH = "build/ecdsa_verify_pubkey_to_addr/verification_key.json";

const verify = async (proof, publicSignals) => {
  const vKey = JSON.parse(fs.readFileSync(VKEY_PATH));
  const result = await snarkJs.groth16.verify(
    vKey,
    publicSignals,
    proof,
    console
  );

  if (result) {
    console.log("Proof verified!");
  } else {
    console.log("Proof verification failed");
  }
};

const prove = async () => {
  if (!fs.existsSync(ZKEY_PATH)) {
    console.log(
      "zkey not found. Please run `yarn build:ecdsa_verify_pubkey_to_addr` first"
    );
    return;
  }

  console.time("Full proof generation");

  const msgHash = hashPersonalMessage(Buffer.from("hello world"));

  const pubKey = ec.keyFromPrivate(privKey.toString(16)).getPublic();

  const address = BigInt(
    `0x${publicToAddress(
      Buffer.from(pubKey.encode("hex").substring(2), "hex")
    ).toString("hex")}`
  );

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

  console.log("Calculating point cache...");
  console.time("Point cache calculation");
  const TPreComputes = getPointPreComputes(T);
  console.timeEnd("Point cache calculation");

  const input = {
    TPreComputes,
    U: [splitToRegisters(U.x), splitToRegisters(U.y)],
    s: [splitToRegisters(s.toString("hex"))]
  };

  console.log("Proving...");
  const { publicSignals, proof } = await snarkJs.groth16.fullProve(
    input,
    "build/ecdsa_verify_pubkey_to_addr/build_ecdsa_verify_pubkey_to_addr_js/build_ecdsa_verify_pubkey_to_addr.wasm",
    ZKEY_PATH
  );

  const outputAddress = publicSignals[0];

  if (outputAddress === address.toString(10)) {
    console.log("Success!");
    console.timeEnd("Full proof generation");
  } else {
    console.log("Output address doesn't match the expected address");
  }

  // Now, verify the proof
  await verify(proof, publicSignals);

  process.exit(0);
};

prove();

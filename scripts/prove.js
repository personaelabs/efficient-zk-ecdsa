const snarkJs = require("snarkjs");
const {
  hashPersonalMessage,
  ecsign,
  privateToAddress
} = require("@ethereumjs/util");
const { BASE_R_SECP256K1_TEMPLATE, SECP256K1_N } = require("./config");
const elliptic = require("@DanTehrani/elliptic");
const EC = require("@DanTehrani/elliptic").ec;
const defineCurve = require("@DanTehrani/elliptic").curves.defineCurve;
const ec = new elliptic.ec("secp256k1");
const BN = require("bn.js");
const { splitToRegisters } = require("./utils");
const { downloadZKey } = require("./download-zkey");
const fs = require("fs");
const crypto = require("crypto");

const privKey = BigInt(
  "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
);

const MSG_2 = hashPersonalMessage(Buffer.from("This message should be public"));

// Compute r^-1 * pubKey2
const computeModInvRMultPubKey2 = (r, pubKey2) => {
  const rRed = new BN(r);
  const modInvR = rRed.invm(SECP256K1_N); // r^-1

  const modInvRMultPubKey2 = pubKey2.mul(modInvR); // pubKey2 * r^-1
  return modInvRMultPubKey2;
};

const prove = async () => {
  if (!fs.existsSync("circuit.zkey")) {
    console.log("Downloading proving key...");
    await downloadZKey();
    console.log("...done");
  }

  console.time("Full proof generation");

  const secretMessage = Buffer.from(crypto.randomBytes(32));
  const secretMessageHash = hashPersonalMessage(secretMessage);

  console.log(`Signing secret message 0x${secretMessage.toString("hex")}`);

  const addr = privateToAddress(
    Buffer.from(privKey.toString(16), "hex")
  ).toString("hex");

  const { v, r, s } = ecsign(secretMessageHash, privKey);

  /*
    If R.y is odd, then recovery_id is 1 or 3. If y is even, then recovery_id is 0 or 2.
    And recovery_id := v - 27
  */
  const isYOdd = (v - BigInt(27)) % BigInt(2);
  const rPoint = ec.keyFromPublic(
    ec.curve.pointFromX(new BN(r), isYOdd).encode("hex"),
    "hex"
  );

  // Define a curve with generator point R
  defineCurve("r", {
    ...BASE_R_SECP256K1_TEMPLATE,
    g: [rPoint.pub.x.toString("hex"), rPoint.pub.y.toString("hex")]
  });

  const baseRSecp256k1 = EC("r");

  // Generate a signature using s as the secret key, with the generator point R
  const sig2 = baseRSecp256k1.keyFromPrivate(new BN(s)).sign(MSG_2);

  const r2 = sig2.r;
  const s2 = sig2.s;

  const r2Point = ec.keyFromPublic(
    ec.curve.pointFromX(r2, sig2.recoveryParam).encode("hex"),
    "hex"
  );

  // pubKey2 = s * R
  const pubKey2 = rPoint.getPublic().mul(new BN(s));

  // Verify the second signature by checking s2 * R2 = msg2 * R + r2 * pubKey2
  const s2MulR2 = r2Point.getPublic().mul(s2);
  const msg2MulR = rPoint.getPublic().mul(MSG_2);
  const r2MulPubKey2 = ec
    .keyFromPublic(pubKey2.encode("hex"), "hex")
    .getPublic()
    .mul(r2);

  if (!s2MulR2.eq(msg2MulR.add(r2MulPubKey2))) {
    throw new Error("Second the signature is invalid!");
  }

  const modInvRMultPubKey2 = computeModInvRMultPubKey2(r, pubKey2);

  const rRed = new BN(r);
  // -(r^-1 * msg)
  const negMsgMultModInvR = rRed
    .invm(SECP256K1_N)
    .mul(new BN(secretMessageHash))
    .neg()
    .umod(SECP256K1_N);

  const input = {
    modInvRMultPubKey2: [
      splitToRegisters(modInvRMultPubKey2.x),
      splitToRegisters(modInvRMultPubKey2.y)
    ],
    negMsgMultModInvR: splitToRegisters(negMsgMultModInvR)
  };

  console.log("Proving...");
  const { publicSignals, proof } = await snarkJs.groth16.fullProve(
    input,
    "circuit.wasm",
    "circuit.zkey"
  );

  const derivedAddress = BigInt(publicSignals[0]).toString(16);

  if (derivedAddress === addr) {
    console.log("Verified!");
    console.log("Prover address:", addr);
    console.log("Derived address:", derivedAddress);
  } else {
    console.log("Verification failed!");
    console.log("Prover address:", addr);
    console.log("Derived address:", derivedAddress);
  }

  console.timeEnd("Full proof generation");
  process.exit();
};

prove();

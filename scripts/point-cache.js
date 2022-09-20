const elliptic = require("@DanTehrani/elliptic");
const ec = new elliptic.ec("secp256k1");
const BN = require("bn.js");
const { splitToRegisters } = require("./utils");
const { STRIDE, NUM_STRIDES } = require("./config");

const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

const ecCachedWindowed = point => {
  const keyPoint = ec.keyFromPublic({
    x: Buffer.from(point.x.toString(16), "hex"),
    y: Buffer.from(point.y.toString(16), "hex")
  });

  const gPowers = []; // [32][256][2][4]
  for (let i = 0n; i < NUM_STRIDES; i++) {
    const stride = [];
    const power = 2n ** (i * STRIDE);
    for (let j = 0n; j < 2n ** STRIDE; j++) {
      const l = j * power;

      const gPower = keyPoint.getPublic().mul(new BN(l));

      const x = splitToRegisters(gPower.x);
      const y = splitToRegisters(gPower.y);

      stride.push([x, y]);
    }
    gPowers.push(stride);
  }

  return gPowers;
};

const computeModInvRMultGCache = r => {
  const rRed = new BN(r);
  const modInvR = rRed.invm(SECP256K1_N); // r^-1

  return ecCachedWindowed(ec.curve.g.mul(modInvR).neg());
};

const computeModInvRMultPubKey2 = (r, pubKey2) => {
  const rRed = new BN(r);
  const modInvR = rRed.invm(SECP256K1_N); // r^-1

  const modInvRMultPubKey2 = pubKey2.mul(modInvR); // pubKey2 * r^-1
  return modInvRMultPubKey2;
};

module.exports = {
  computeModInvRMultGCache,
  computeModInvRMultPubKey2
};

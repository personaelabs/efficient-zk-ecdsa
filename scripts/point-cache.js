const elliptic = require("@DanTehrani/elliptic");
const ec = new elliptic.ec("secp256k1");
const BN = require("bn.js");
const { splitToRegisters } = require("./utils");
const { STRIDE, NUM_STRIDES, SECP256K1_N } = require("./config");

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

module.exports = {
  computeModInvRMultGCache
};

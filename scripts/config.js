const BN = require("bn.js");

const STRIDE = 8n;
const NUM_STRIDES = 256n / STRIDE; // = 32
const REGISTERS = 4n;

const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

module.exports = {
  STRIDE,
  NUM_STRIDES,
  REGISTERS,
  SECP256K1_N
};

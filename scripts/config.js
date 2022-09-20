const hash = require("hash.js");

const STRIDE = 8n;
const NUM_STRIDES = 256n / STRIDE; // = 32
const REGISTERS = 4n;

const BASE_R_SECP256K1_TEMPLATE = {
  type: "short",
  prime: "k256",
  p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",
  a: "0",
  b: "7",
  n: "ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141",
  h: "1",
  hash: hash.sha256,
  gRed: false,
  g: [
    // x and y coordinates of the generator point which is the point R in our case
  ]
};

module.exports = {
  STRIDE,
  NUM_STRIDES,
  REGISTERS,
  BASE_R_SECP256K1_TEMPLATE
};

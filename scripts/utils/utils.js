const { REGISTERS } = require("./config");

const addHexPrefix = str => `0x${str}`;

const splitToRegisters = value => {
  const registers = [];

  if (!value) {
    return [0n, 0n, 0n, 0n];
  }

  const hex = value.toString(16).padStart(64, "0");
  for (let k = 0; k < REGISTERS; k++) {
    // 64bit = 16 chars in hex
    const val = hex.slice(k * 16, (k + 1) * 16);

    registers.unshift(BigInt(addHexPrefix(val)));
  }

  return registers.map(el => el.toString());
};

const registersToHex = registers => {
  return registers
    .map(el => BigInt(el).toString(16).padStart(16, "0"))
    .join("");
};

module.exports = {
  registersToHex,
  splitToRegisters
};

import { expose } from "comlink";

const fetch_params = async () => {
  const response = await fetch("http://localhost:3000/kzg_bn254_18.params");
  const bytes = await response.arrayBuffer();

  const params = new Uint8Array(bytes);
  return params;
};

export const generateProof = async () => {
  console.log("gen proof");

  const params = await fetch_params();
  console.log("params", params.length);

  const {
    default: init,
    initThreadPool,
    prove,
    init_panic_hook
  } = await import("./wasm/halo2_efficient_ecdsa.js");

  await init();
  await init_panic_hook();
  await initThreadPool(navigator.hardwareConcurrency);
  console.log("here we go");
  console.time("Full proving time");
  const proof = await prove(params);
  console.timeEnd("Full proving time");
  console.log("proof", proof);
};

const exports = {
  generateProof
};
export type Halo2Prover = typeof exports;

expose(exports);

// wasm_bindgen_rayon requires the rustflags defined in .cargo/config
// to be set in order to compile. When we enable rustflags,
// rust-analyzer (the vscode extension) stops working, so by default,
// we don't compile wasm_bindgen_rayon which requires rustflags,
#[cfg(target_family = "wasm")]
pub use wasm_bindgen_rayon::init_thread_pool;

use crate::circuits::ecc_circuit::EccCircuit;

use halo2_proofs::pasta::EqAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

use rand_core::OsRng;
use serde_wasm_bindgen;
use std::io::BufReader;
use wasm_bindgen::prelude::*;

use web_sys;

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn prove_scalar_mult() -> JsValue {
    let empty_circuit = EccCircuit {};

    let k = 11;
    let params: Params<EqAffine> = Params::new(k);

    web_sys::console::time_with_label("vkey generation");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    web_sys::console::time_end_with_label("vkey generation");

    web_sys::console::time_with_label("vkey generation");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    web_sys::console::time_end_with_label("pkey generation");

    let circuit = EccCircuit {};

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    web_sys::console::time_with_label("proof generation");
    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof: Vec<u8> = transcript.finalize();
    web_sys::console::time_end_with_label("proof generation");

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

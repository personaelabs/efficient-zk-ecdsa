use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
// wasm_bindgen_rayon requires the rustflags defined in .cargo/config
// to be set in order to compile. When we enable rustflags,
// rust-analyzer (the vscode extension) stops working, so by default,
// we don't compile wasm_bindgen_rayon which requires rustflags,
#[cfg(target_family = "wasm")]
pub use wasm_bindgen_rayon::init_thread_pool;

use crate::circuits::precompute_circuit::EfficientECDSAPrecomputeCircuit;
use console_error_panic_hook;

use halo2_proofs::pasta::{Eq, EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
    Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
};

use js_sys::Uint8Array;
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
pub fn prove(v_key_ser: JsValue, params_ser: JsValue) -> JsValue {
    web_sys::console::time_with_label("kzg params setup");
    let params_vec = Uint8Array::new(&params_ser).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params_vec[..])).unwrap();

    let vk_vec = Uint8Array::new(&v_key_ser).to_vec();

    web_sys::console::time_end_with_label("kzg params setup");

    let input = generate_precompute_input();
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();

    let efficient_ecdsa_circuit = EfficientECDSAPrecomputeCircuit::<Secp256k1Affine, Fr> {
        aux_generator,
        window_size: 4,
        public_key: input.public_key,
        t_powers: input.t_powers,
        u: input.u,
        s: input.s,
        ..Default::default()
    };

    let vk =
        bn_256_read_vkey::<EfficientECDSAPrecomputeCircuit<Secp256k1Affine, Fr>>(&vk_vec, &params);

    web_sys::console::time_with_label("pkey generation");
    let pk = bn_256_pkeygen(&params, vk, &efficient_ecdsa_circuit);
    web_sys::console::time_end_with_label("pkey generation");

    web_sys::console::time_with_label("proving");
    let proof = bn_256_prove(efficient_ecdsa_circuit, &params, &[&[&[]]], &pk);
    web_sys::console::time_end_with_label("proving");

    log!("Proof generated!");

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify(proof_ser: JsValue, params_ser: JsValue) -> JsValue {
    let params_vec = Uint8Array::new(&params_ser).to_vec();
    let params: ParamsVerifierKZG<Bn256> =
        Params::<G1Affine>::read(&mut BufReader::new(&params_vec[..])).unwrap();

    let proof = serde_wasm_bindgen::from_value::<Vec<u8>>(proof_ser).unwrap();

    let empty_circuit = EfficientECDSAPrecomputeCircuit::<Secp256k1Affine, Fr> {
        ..Default::default()
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let result = bn_256_verify(&proof, &params, &vk, &[&[&[]]]);
    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn ecc_scalar_mult_prove() -> JsValue {
    let much_too_small_params: Params<EqAffine> = Params::new(1);

    web_sys::console::time_with_label("vkey generation");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    web_sys::console::time_end_with_label("vkey generation");

    web_sys::console::time_with_label("pkey generation");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    web_sys::console::time_end_with_label("pkey generation");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[circuit.clone(), circuit.clone()],
        &[&[&[instance]], &[&[instance]]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

use halo2_efficient_ecdsa::{
    circuits::precompute_circuit::EfficientECDSAPrecomputeCircuit,
    ecdsa_helper::{bn_256_vkeygen, generate_precompute_input},
};
use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;

use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::bn256::{Bn256, Fr},
    halo2curves::group::{Curve, Group},
};

use rand_core::OsRng;

// Generate the verification key of EfficientECDSAPrecomputeCircuit and output it as a binary.
fn main() {
    type E = Secp256k1Affine;
    type N = Fr;
    let input = generate_precompute_input::<E>();
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();
    let window_size = 2;

    let circuit = EfficientECDSAPrecomputeCircuit::<E, N> {
        aux_generator,
        window_size,
        public_key: input.public_key,
        t_powers: input.t_powers,
        u: input.u,
        s: input.s,
        ..Default::default()
    };

    let mut kzg_params_file =
        std::fs::File::open("./browser_benchmark/public/kzg_bn254_18.params").unwrap();
    let kzg_params = ParamsKZG::<Bn256>::read(&mut kzg_params_file).unwrap();

    let mut v_key_file = std::fs::File::create("./vk.vkey").unwrap();
    let vk = bn_256_vkeygen(&kzg_params, &circuit);
    vk.write(&mut v_key_file).unwrap();
}

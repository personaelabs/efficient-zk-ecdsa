use crate::constants::{BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use crate::get_powers::get_powers;
use ecc::maingate::{big_to_fe, fe_to_big};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::kzg::{
    commitment::KZGCommitmentScheme,
    multiopen::{ProverSHPLONK, VerifierSHPLONK},
    strategy::SingleStrategy,
};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::group::Curve,
    plonk::*,
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand_core::OsRng;
use std::io::prelude::*;
use std::ops::Neg;

// This file consists of functions relating
// to operation around generating the circuit inputs.

#[derive(Debug)]
pub struct Signature<E: CurveAffine> {
    public_key: E,
    r_point: E,
    s: E::Scalar,
    msg_hash: E::Scalar,
}

pub struct VanillaInput<E: CurveAffine> {
    pub public_key: Value<E>,
    pub t: Value<E>,
    pub u: Value<E>,
    pub s: Value<E::Scalar>,
}

pub struct PrecomputeInput<E: CurveAffine> {
    pub public_key: Value<E>,
    pub t_powers: Vec<E>,
    pub u: Value<E>,
    pub s: Value<E::Scalar>,
}

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

// Generate ECDSA signature from a random key pair
fn generate_sig<C: CurveAffine>() -> Signature<C> {
    let g = C::generator();

    let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <C as CurveAffine>::ScalarExt::random(OsRng);

    // Draw arandomness
    let k = <C as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let r_point = (g * k).to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = mod_n::<C>(*x);

    // Calculate `s`
    let s = k_inv * (msg_hash + (r * sk));

    Signature {
        public_key,
        r_point: (g * k).to_affine(),
        s,
        msg_hash,
    }
}

// Generate precompute circuit input
pub fn generate_vanilla_input<E: CurveAffine>() -> VanillaInput<E> {
    let signature = generate_sig::<E>();

    let public_key = signature.public_key;
    let s = signature.s;
    let r_point = signature.r_point;
    // Extract x-coordinate of r
    let r = mod_n::<E>(*r_point.coordinates().unwrap().x());
    let msg_hash = signature.msg_hash;

    // r_inv = r^-1
    let r_inv = r.invert().unwrap();
    // w = -(r^-1 * msg)
    let w = (r_inv * msg_hash).neg();

    let g = E::generator();
    // U = -(w * G) = -(r^-1 * msg * G)
    let u_point = g * w;

    // T = r^-1 * R
    let t_point = r_point * r_inv;

    VanillaInput {
        public_key: Value::known(public_key),
        t: Value::known(t_point.to_affine()),
        u: Value::known(u_point.to_affine()),
        s: Value::known(s),
    }
}

// Generate precompute circuit input
pub fn generate_precompute_input<E: CurveAffine>() -> PrecomputeInput<E> {
    let signature = generate_sig::<E>();

    let public_key = signature.public_key;
    let s = signature.s;
    let r_point = signature.r_point;
    // Extract x-coordinate of r
    let r = mod_n::<E>(*r_point.coordinates().unwrap().x());
    let msg_hash = signature.msg_hash;

    // r_inv = r^-1
    let r_inv = r.invert().unwrap();
    // w = -(r^-1 * msg)
    let w = (r_inv * msg_hash).neg();

    let g = E::generator();
    // U = -(w * G) = -(r^-1 * msg * G)
    let u_point = g * w;

    // T = r^-1 * R
    let t_point = r_point * r_inv;
    let t_powers = get_powers::<E, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(t_point.to_affine());

    PrecomputeInput {
        public_key: Value::known(public_key),
        t_powers: t_powers,
        u: Value::known(u_point.to_affine()),
        s: Value::known(s),
    }
}

pub fn bn_256_pkeygen(
    params: &ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
    circuit: &impl Circuit<Fr>,
) -> ProvingKey<G1Affine> {
    let pk = keygen_pk(params, vk, circuit).expect("keygen_pk should not fail");
    pk
}

pub fn bn_256_vkeygen(
    params: &ParamsKZG<Bn256>,
    circuit: &impl Circuit<Fr>,
) -> VerifyingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();

    vk
}

pub fn bn_256_read_vkey<ConcreteCircuit>(
    mut v_key_ser: &[u8],
    params: &ParamsKZG<Bn256>,
) -> VerifyingKey<G1Affine>
where
    ConcreteCircuit: Circuit<Fr>,
{
    let vk =
        VerifyingKey::<G1Affine>::read::<&[u8], ConcreteCircuit>(&mut v_key_ser, params).unwrap();

    vk
}

pub fn bn_256_prove<ConcreteCircuit>(
    circuit: ConcreteCircuit,
    params: &ParamsKZG<Bn256>,
    instances: &[&[&[Fr]]],
    pk: &ProvingKey<G1Affine>,
) -> Vec<u8>
where
    ConcreteCircuit: Circuit<Fr>,
{
    let rng = rand::thread_rng();

    let circuits = [circuit];
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        ConcreteCircuit,
    >(params, pk, &circuits, instances, rng, &mut transcript)
    .unwrap();

    let proof: Vec<u8> = transcript.finalize();

    proof
}

pub fn bn_256_verify(
    proof: &[u8],
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    instances: &[&[&[Fr]]],
) -> bool {
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let strategy: SingleStrategy<Bn256> = SingleStrategy::new(&params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&params, &vk, strategy, instances, &mut transcript)
    .is_ok()
}

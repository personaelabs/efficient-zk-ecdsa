use crate::chips::vanilla_chip::{EfficientECDSAVanillaChip, EfficientECDSAVanillaConfig};
use crate::constants::{BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::circuit::Value;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};

use halo2_proofs::plonk::*;

use std::marker::PhantomData;

#[derive(Default)]
pub struct EfficientECDSAVanillaCircuit<E: CurveAffine, N: FieldExt> {
    pub public_key: Value<E>,
    pub t: Value<E>,
    pub u: Value<E>,
    pub s: Value<E::Scalar>,

    pub aux_generator: E,
    pub window_size: usize,
    pub _marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt> Circuit<N> for EfficientECDSAVanillaCircuit<E, N> {
    type Config = EfficientECDSAVanillaConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        EfficientECDSAVanillaChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<N>) -> Result<(), Error> {
        let chip = EfficientECDSAVanillaChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config);

        chip.verify(
            layouter,
            self.aux_generator,
            self.window_size,
            self.s,
            self.t,
            self.u,
            self.public_key,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa_helper::{
        bn_256_pkeygen, bn_256_prove, bn_256_vkeygen, generate_vanilla_input,
    };
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;

    use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
    use halo2_proofs::halo2curves::group::{Curve, Group};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use rand_core::OsRng;

    use ark_std::{end_timer, start_timer};

    #[test]
    fn test_mock() {
        // Generate signature and get the pre-computed values.
        type E = Secp256k1Affine;
        type N = Fr;

        let input = generate_vanilla_input::<E>();

        let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();

        let circuit = EfficientECDSAVanillaCircuit::<E, N> {
            aux_generator,
            window_size: 2,
            public_key: input.public_key,
            t: input.t,
            u: input.u,
            s: input.s,
            ..Default::default()
        };

        let instance = vec![vec![]];

        let prover =
            MockProver::run::<EfficientECDSAVanillaCircuit<E, N>>(18, &circuit, instance).unwrap();
        prover.assert_satisfied();
    }

    #[cfg(test)]
    #[test]
    fn test_vanilla_full_prove() -> Result<(), Error> {
        use crate::ecdsa_helper::bn_256_verify;

        let window_size = 4;
        // constructing circuit from a sample input
        let circuit_time = start_timer!(|| "Time elapsed circuit construction");
        type E = Secp256k1Affine;
        type N = Fr;
        let input = generate_vanilla_input::<E>();
        let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();

        let circuit = EfficientECDSAVanillaCircuit::<E, N> {
            aux_generator,
            window_size,
            public_key: input.public_key,
            t: input.t,
            u: input.u,
            s: input.s,
            ..Default::default()
        };
        end_timer!(circuit_time);

        // constructing vkey
        // Read the KZG params
        let mut f = std::fs::File::open("./browser_benchmark/public/kzg_bn254_18.params").unwrap();
        let kzg_params = ParamsKZG::<Bn256>::read(&mut f).unwrap();

        // Benchmark verifying-key generation
        let v_keygen = start_timer!(|| "Verifying key gen");
        let vk = bn_256_vkeygen(&kzg_params, &circuit);
        end_timer!(v_keygen);

        // Benchmark proving-key generation
        let p_keygen = start_timer!(|| "Proving key gen");
        let pk = bn_256_pkeygen(&kzg_params, vk.clone(), &circuit);
        end_timer!(p_keygen);

        // Benchmark proof generation
        let prove = start_timer!(|| "Prove");
        let proof = bn_256_prove(circuit, &kzg_params, &[&[&[]]], &pk);
        end_timer!(prove);

        let verify = start_timer!(|| "Verify");
        let result = bn_256_verify(&proof, &kzg_params, &vk, &[&[&[]]]);
        assert_eq!(result, true);
        end_timer!(verify);

        Ok(())
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_vanilla_circuit() {
        use crate::plot;

        type E = Secp256k1Affine;
        type N = Fr;
        let circuit = EfficientECDSAVanillaCircuit::<E, N> {
            window_size: 4,
            ..Default::default()
        };

        plot::plot("vanilla", &circuit);
    }
}

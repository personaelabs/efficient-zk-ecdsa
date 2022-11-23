//! This circuit exists only for the purpose of benchmarking.

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::*;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error, Expression};
use std::array;
use std::marker::PhantomData;
use zkevm_circuits::keccak_circuit::keccak_packed_multi::KeccakPackedConfig as KeccakConfig;

pub const MOCK_RANDOMNESS: u64 = 0x100;

pub struct KeccakCircuit<F: Field> {
    pub keccak_inputs: Vec<Vec<u8>>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            keccak_inputs: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let power_of_randomness = array::from_fn(|i| {
            Expression::Constant(F::from(MOCK_RANDOMNESS).pow(&[1 + i as u64, 0, 0, 0]))
        });

        KeccakConfig::configure(meta, power_of_randomness[0].clone())
    }

    fn synthesize(
        &self,
        keccak_circuit: Self::Config,
        layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        keccak_circuit.load(&mut layouter)?;
        keccak_circuit.assign_from_witness(
            &mut layouter,
            &self.keccak_inputs,
            F::from(MOCK_RANDOMNESS),
            None,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::circuit::{Cell, Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::{Eq, EqAffine, Fp};
    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
        Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
    };
    use halo2_proofs::poly::{commitment::Params, Rotation};

    #[test]
    fn test_keccak() {
        let circuit = KeccakCircuit {
            keccak_inputs: vec![vec![0u8; 32]; 2],
            _marker: PhantomData,
        };
        let k = 5;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_full_prove() {
        let empty_circuit = KeccakCircuit {
            keccak_inputs: Value::unknown(),
            _marker: PhantomData,
        };

        let k = 5;
        let params: Params<EqAffine> = Params::new(k);

        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

        let circuit = KeccakCircuit {
            keccak_inputs: vec![vec![0u8; 32]; 2],
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}

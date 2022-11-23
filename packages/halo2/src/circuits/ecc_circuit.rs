//! This circuit exists only for the purpose of benchmarking.

use ff::PrimeFieldBits;
use halo2_gadgets::ecc::{
    chip::{EccChip, EccConfig, H},
    FixedPoints, NonIdentityPoint,
};
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_gadgets::utilities::UtilitiesInstructions;
use halo2_proofs::arithmetic::{CurveAffine, Field, FieldExt};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::group::{Curve, Group};
use halo2_proofs::pasta::pallas;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error, Expression};
use std::marker::PhantomData;

pub struct EccCircuit {}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct TestFixedBases;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct FullWidth(pallas::Affine, &'static [(u64, [pallas::Base; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Short;

impl FixedPoints<pallas::Affine> for TestFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}

impl Circuit<pallas::Base> for EccCircuit {
    type Config = EccConfig<TestFixedBases>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {}
    }
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let lookup_table = meta.lookup_table_column();
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        // Shared fixed column for loading constants
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
        EccChip::<TestFixedBases>::configure(meta, advices, lagrange_coeffs, range_check)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let chip = EccChip::construct(config.clone());

        // Load 10-bit lookup table. In the Action circuit, this will be
        // provided by the Sinsemilla chip.
        //        config.lookup_config.load(&mut layouter)?;
        let p_val = pallas::Point::random(rand::rngs::OsRng).to_affine(); // P
        let p = NonIdentityPoint::new(
            chip.clone(),
            layouter.namespace(|| "P"),
            Value::known(p_val),
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
    fn test_ecc() {
        let circuit = EccCircuit {};
        let k = 5;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_full_prove() {
        let empty_circuit = EccCircuit {};

        let k = 5;
        let params: Params<EqAffine> = Params::new(k);

        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

        let circuit = EccCircuit {};

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}

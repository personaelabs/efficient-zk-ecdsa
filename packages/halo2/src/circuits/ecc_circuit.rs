//! This circuit exists only for the purpose of benchmarking.

use crate::circuits::constants::*;
use halo2_gadgets::ecc::{
    chip::{EccChip, EccConfig},
    NonIdentityPoint, ScalarVar,
};
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_gadgets::utilities::UtilitiesInstructions;
use halo2_proofs::arithmetic::{Field, FieldExt};
use halo2_proofs::circuit::{Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::group::{Curve, Group};
use halo2_proofs::pasta::pallas;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use rand_core::OsRng;

#[derive(Clone)]
pub struct EccCircuit {}

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
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let chip = EccChip::construct(config.clone());

        // Load lookup table for range check
        chip.config().lookup_config.load(&mut layouter)?;

        let p_val = pallas::Point::generator().to_affine();
        let p = NonIdentityPoint::new(
            chip.clone(),
            layouter.namespace(|| "P"),
            Value::known(p_val),
        )?;

        let column = chip.config().advices[0];
        let one_val = pallas::Base::one();

        let one = chip.load_private(
            layouter.namespace(|| "random scalar"),
            column,
            Value::known(one_val),
        )?;

        let one = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "ScalarVar from_base"),
            &one,
        )?;

        // 1 * G
        let result = p.mul(layouter.namespace(|| "ScalarVar mul"), one)?;

        result.0.constrain_equal(layouter, &p)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::EqAffine;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

    #[test]
    fn test_ecc() {
        let circuit = EccCircuit {};
        let k = 11;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_full_prove() {
        let empty_circuit = EccCircuit {};

        let k = 11;
        let params: Params<EqAffine> = Params::new(k);

        let vkey_gen = start_timer!(|| "vkey gen");
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        end_timer!(vkey_gen);

        let pkey_gen = start_timer!(|| "pkey gen");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        end_timer!(pkey_gen);

        let circuit = EccCircuit {};

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let proof_gen = start_timer!(|| "proof gen");
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
        end_timer!(proof_gen);

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let verification = start_timer!(|| "verification");
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        end_timer!(verification);
    }
}

use ecc::{AssignedPoint, EccConfig, GeneralEccChip};
use ff::Field;
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::secp256k1::{self, Secp256k1, Secp256k1Affine};
use halo2_proofs::plonk::{ConstraintSystem, Error};
use integer::{IntegerInstructions, Range};
use maingate::{
    AssignedCondition, MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions,
    RegionCtx,
};
use std::fmt::Debug;
use std::marker::PhantomData;

struct Table<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>(
    pub(crate) Vec<AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
);

// EfficientECDSAChip consists of 3 chips
// MainGate, RangeChip, and GeneralEccChip,
// and its own gates.
// (Note that there are also sub-chips that construct those 3 chips.)
#[derive(Clone, Debug)]
pub struct EfficientECDSAVanillaConfig {
    pub main_gate_config: MainGateConfig,
    pub range_config: RangeConfig,
    pub ecc_config: EccConfig,
}
pub struct EfficientECDSAVanillaChip<
    E: CurveAffine,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    config: EfficientECDSAVanillaConfig,
    _marker: (PhantomData<E>, PhantomData<N>),
}

impl<E: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    EfficientECDSAVanillaChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(config: EfficientECDSAVanillaConfig) -> Self {
        Self {
            config,
            _marker: (PhantomData, PhantomData),
        }
    }

    fn config_maingate_chip(meta: &mut ConstraintSystem<N>) -> MainGateConfig {
        MainGate::<N>::configure(meta)
    }

    fn config_range_chip(
        meta: &mut ConstraintSystem<N>,
        main_gate_config: MainGateConfig,
    ) -> RangeConfig {
        let (rns_base, rns_scalar) = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        RangeChip::<N>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        )
    }

    fn config_ecc_chip(range_config: RangeConfig, main_gate_config: MainGateConfig) -> EccConfig {
        // GeneralEccChip doesn't implement "configure" method.
        // Instead, "EccConfig" has a "new" method to configure itself. (probably)
        EccConfig::new(range_config, main_gate_config)
    }

    pub fn configure(meta: &mut ConstraintSystem<N>) -> EfficientECDSAVanillaConfig {
        // Configure all the chips
        let main_gate_config = Self::config_maingate_chip(meta);
        let range_config = Self::config_range_chip(meta, main_gate_config.clone());
        let ecc_config = Self::config_ecc_chip(range_config.clone(), main_gate_config.clone());

        EfficientECDSAVanillaConfig {
            main_gate_config,
            range_config,
            ecc_config,
        }
    }

    pub fn verify(
        &self,
        mut layouter: impl Layouter<N>,
        aux_generator: E,
        window_size: usize,
        s: Value<E::Scalar>,
        t: Value<E>,
        u: Value<E>,
        pk: Value<E>,
    ) -> Result<(), Error> {
        // Instantiate the GeneralEccChip
        let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            self.config.ecc_config.clone(),
        );

        // Instantiate the RangeChip
        let range_chip = RangeChip::<N>::new(self.config.range_config.clone());
        range_chip.load_table(&mut layouter)?;

        layouter.assign_region(
            || "assign aux values",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                ecc_chip.assign_aux_generator(ctx, Value::known(aux_generator))?;
                ecc_chip.assign_aux(ctx, window_size, 1)?;
                Ok(())
            },
        )?;

        let scalar_chip = ecc_chip.scalar_field_chip();

        layouter.assign_region(
            || "verify",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                // Rns representation
                let bigint_s = ecc_chip.new_unassigned_scalar(s);

                // Range checked values?
                let s_assigned = scalar_chip.assign_integer(ctx, bigint_s, Range::Remainder)?;
                let t_assigned = ecc_chip.assign_point(ctx, t)?;
                let u_assigned = ecc_chip.assign_point(ctx, u)?;

                let pk_assigned = ecc_chip.assign_point(ctx, pk)?;

                // s * T
                let s_mul_t = ecc_chip.mul(ctx, &t_assigned, &s_assigned, window_size)?;

                // u + s * T
                let derived_pub_key = ecc_chip.add(ctx, &s_mul_t, &u_assigned).unwrap();

                // Check that the derived public key equals to the given public key
                ecc_chip.assert_equal(ctx, &derived_pub_key, &pk_assigned)?;
                Ok(())
            },
        )?;

        Ok(())
    }

    // Expose public values here
}

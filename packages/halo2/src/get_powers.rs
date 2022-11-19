use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::halo2curves::group::Curve;

pub fn get_powers<
    E: CurveAffine,
    F: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(
    point: E,
) -> Vec<E> {
    let mut powers = vec![];

    for i in 0..256 {
        let power = E::ScalarExt::from(2).pow(&[i as u64, 0, 0, 0]);
        let point_power = point * power;
        //        let point_power_in_rns = ecc_chip.to_rns_point(point_power.into());
        powers.push(point_power.to_affine());
    }

    powers
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::{bn256::Fr, secp256k1::Secp256k1Affine};

    use super::*;

    #[test]
    fn test_get_powers() {
        type E = Secp256k1Affine;
        // Test using the generator point of secp256k1 for convenience in debugging
        let point = E::generator();

        // For now, just check if this runs without panicking
        get_powers::<E, Fr, 4, 68>(point);
    }
}

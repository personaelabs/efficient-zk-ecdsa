use halo2_proofs::{halo2curves::FieldExt, plonk::Circuit};

pub fn plot<F: FieldExt, ConcreteCircuit: Circuit<F>>(label: &str, circuit: &ConcreteCircuit) {
    use plotters::prelude::*;

    let filename = &[label, ".png"].join("");
    let root = BitMapBackend::new(filename, (1024, 3096)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled(label, ("sans-serif", 60)).unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .render(18, circuit, &root)
        .unwrap();
}

use ark_ec::bls12::Bls12;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_gemini::circuit::{dummy_r1cs, generate_relation};
use ark_gemini::iterable::dummy::{dummy_r1cs_stream, DummyStreamer};
use ark_gemini::kzg::CommitterKeyStream;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::test_rng;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_ec::bn::Bn;
use ark_relations::r1cs::ConstraintSystem;

use clap::Parser;

type G1 = <Bn<ark_bn254::Config> as Pairing>::G1Affine;
type G2 = <Bn<ark_bn254::Config> as Pairing>::G2Affine;
type Proof = ark_gemini::snark::Proof<ark_bn254::Bn254>;

/// Start a watcher thread that will print the memory (stack+heap) currently allocated at regular intervals.
/// Informations are going to be printed only with feature "print-trace" enabled, and within a linux system.
pub fn memory_traces() {
    #[cfg(all(feature = "print-trace", target_os = "linux"))]
    {
        // virtual memory page size can be obtained also with:
        // $ getconf PAGE_SIZE    # alternatively, PAGESIZE
        let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let mut previous_memory = 0usize;

        ark_std::thread::spawn(move || loop {
            // obtain the total virtual memory size, in pages
            // and convert it to bytes
            let pages_used = procinfo::pid::statm_self().unwrap().data;
            let memory_used = pagesize * pages_used;

            // if the memory changed of more than 10kibibytes from last clock tick,
            // then log it.
            if (memory_used - previous_memory) > 10 << 10 {
                log::debug!("memory (statm.data): {}B", memory_used);
                previous_memory = memory_used;
            }
            // sleep for 10 seconds
            ark_std::thread::sleep(std::time::Duration::from_secs(10))
        });
    }
}

/// Simple option handling for instance size and prover mode.
#[derive(Parser, Debug)]
#[clap(name = "snark")]
struct SnarkConfig {
    /// Size of the instance to be run (logarithmic)
    #[clap(short, long)]
    instance_logsize: usize,

    #[clap(long)]
    time_prover: bool,
}

// fn elastic_snark_main(rng: &mut impl Rng, instance_logsize: usize) -> Proof {
//     let instance_size = 1 << instance_logsize;
//     let max_msm_buffer = 1 << 20;

//     let g1 = G1::generator();
//     let g2 = G2::generator();
//     let r1cs_stream = dummy_r1cs_stream(rng, instance_size);
//     let ck = CommitterKeyStream {
//         powers_of_g: DummyStreamer::new(g1, instance_size + 1),
//         powers_of_g2: vec![g2; 4],
//     };
//     Proof::new_elastic(r1cs_stream, ck, max_msm_buffer)
// }

fn time_snark_main(rng: &mut impl Rng, instance_logsize: usize) -> Proof {
    let num_constraints = 1 << instance_logsize;
    let num_variables = 1 << instance_logsize;

    // let circuit = ark_gemini::circuit::random_circuit(rng, num_constraints, num_variables);
    // let r1cs = ark_gemini::circuit::generate_relation(circuit);
    // let r1cs = ark_gemini::circuit::dummy_r1cs(rng, num_constraints);

    let cfg = CircomConfig::<Bn254>::new(
        "./test-circuits/mycircuit_js/mycircuit.wasm",
        "./test-circuits/mycircuit.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);
    builder.push_input("d", 4);

    let circom = builder.build().unwrap();
    let r1cs = generate_relation::<
        <Bn<ark_bn254::Config> as Pairing>::ScalarField,
        CircomCircuit<Bn<ark_bn254::Config>>,
    >(circom);
    let ck = ark_gemini::kzg::CommitterKey::<Bn254>::new(num_constraints + num_variables, 5, rng);

    Proof::new_time(&r1cs, &ck)
}

fn main() {
    let rng = &mut test_rng();
    let snark_config = SnarkConfig::parse();
    env_logger::init();
    memory_traces();

    println!(
        "Proving an instance of log size  {}",
        snark_config.instance_logsize
    );
    // let proof = if snark_config.time_prover {
    //     time_snark_main(rng, snark_config.instance_logsize)
    // } else {
    //     elastic_snark_main(rng, snark_config.instance_logsize)
    // };
    let proof = time_snark_main(rng, snark_config.instance_logsize);
    println!("proof-size {}B", proof.compressed_size());
}

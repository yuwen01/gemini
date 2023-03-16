use ark_ec::bn::Bn;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_gemini::circuit::{hashchain_split_z, r1cs_from_circom, repeat_r1cs};
use ark_gemini::iterable::dummy::{ConcatStreamer, DummyStreamer};
use ark_gemini::kzg::CommitterKeyStream;
use ark_gemini::misc::product_matrix_vector;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::test_rng;

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

fn repeat_snark_main(rng: &mut impl Rng, instance_logsize: usize) -> Proof {
    let hashchain_r1cs = r1cs_from_circom(
        "./test-circuits/hashchain_output/hashchain_output.r1cs",
        "./test-circuits/hashchain_output/hashchain_output_js/hashchain_output.wasm",
        "1123123",
    );

    let z_components = hashchain_split_z(hashchain_r1cs.z, 5);

    let hash_r1cs = r1cs_from_circom(
        "./test-circuits/hash_output/hash_output.r1cs",
        "./test-circuits/hash_output/hash_output_js/hash_output.wasm",
        "1123123",
    );

    let z_a_raw = z_components
        .iter()
        .map(|x| product_matrix_vector(&hash_r1cs.a, x.as_slice()))
        .collect::<Vec<_>>();
    let z_b_raw = z_components
        .iter()
        .map(|x| product_matrix_vector(&hash_r1cs.b, x.as_slice()))
        .collect::<Vec<_>>();
    let z_c_raw = z_components
        .iter()
        .map(|x| product_matrix_vector(&hash_r1cs.c, x.as_slice()))
        .collect::<Vec<_>>();

    let z_a = ConcatStreamer::new(&z_a_raw);
    let z_b = ConcatStreamer::new(&z_b_raw);
    let z_c = ConcatStreamer::new(&z_c_raw);

    let repeat_r1cs = repeat_r1cs(&hash_r1cs, 5, &z_components, [z_a, z_b, z_c]);
    let g1 = G1::generator();
    let g2 = G2::generator();
    let ck = CommitterKeyStream {
        powers_of_g: DummyStreamer::new(g1, (1 << (6 * instance_logsize)) + 1),
        powers_of_g2: vec![g2; 4],
    };
    Proof::new_elastic(repeat_r1cs, ck, 1 << 20)
}

fn main() {
    let rng = &mut test_rng();
    let snark_config = SnarkConfig::parse();
    env_logger::init();
    memory_traces();

    println!(
        "Proving an instance of log size {}",
        snark_config.instance_logsize
    );
    let proof = repeat_snark_main(rng, snark_config.instance_logsize);
    println!("proof-size {}B", proof.compressed_size());
}

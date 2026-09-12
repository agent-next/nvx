use std::path::PathBuf;

use agent_harness::mxc_policy::cases::generated_corpus;
use sha2::{Digest, Sha256};

fn main() {
    let cases = generated_corpus();
    let mut bytes = serde_json::to_vec_pretty(&cases).expect("serialize corpus");
    bytes.push(b'\n');
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("mxc-policy")
        .join("cases.json");
    std::fs::write(&path, &bytes).expect("write corpus fixture");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = format!("{:x}", hasher.finalize());
    println!(
        "wrote {} cases to {} sha256={}",
        cases.len(),
        path.display(),
        digest
    );
}

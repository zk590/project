use std::env;
use std::path::PathBuf;

fn main() {
    let staticlib_dir = env::var("MERKLE_PLONK_STATICLIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../3-Plonk/target/release"));

    let staticlib_path = staticlib_dir.join("libmerkle_plonk.a");
    if !staticlib_path.exists() {
        panic!(
            "static library not found: {}. Build it first with: cd /opt/project/3-Plonk && cargo build -p merkle-plonk --release",
            staticlib_path.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", staticlib_dir.display());
    println!("cargo:rustc-link-lib=static=merkle_plonk");
    println!("cargo:rerun-if-env-changed=MERKLE_PLONK_STATICLIB_DIR");
    println!("cargo:rerun-if-changed={}", staticlib_path.display());

    let merkle_staticlib_dir = env::var("MERKLE_STATICLIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../1-Sender/merkle/target/release"));
    let merkle_staticlib_path = merkle_staticlib_dir.join("libmerkle.a");
    if !merkle_staticlib_path.exists() {
        panic!(
            "merkle static library not found: {}. Build it first with: cd /opt/project/1-Sender/merkle && cargo build --release",
            merkle_staticlib_path.display()
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        merkle_staticlib_dir.display()
    );
    println!("cargo:rustc-link-lib=static=merkle");
    println!("cargo:rerun-if-env-changed=MERKLE_STATICLIB_DIR");
    println!(
        "cargo:rerun-if-changed={}",
        merkle_staticlib_path.display()
    );

    let receiver_staticlib_dir = env::var("RECEIVER_PLONK_STATICLIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../2-Receiver/Plonk/target/release"));
    let receiver_staticlib_path = receiver_staticlib_dir.join("libreceiver_plonk.a");
    if !receiver_staticlib_path.exists() {
        panic!(
            "receiver static library not found: {}. Build it first with: cd /opt/project/2-Receiver/Plonk && cargo build --release",
            receiver_staticlib_path.display()
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        receiver_staticlib_dir.display()
    );
    println!("cargo:rustc-link-lib=static=receiver_plonk");
    println!("cargo:rerun-if-env-changed=RECEIVER_PLONK_STATICLIB_DIR");
    println!(
        "cargo:rerun-if-changed={}",
        receiver_staticlib_path.display()
    );
}

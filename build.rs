use rustc_version::{version_meta, Channel};

fn main() {
    //
    // This is here mostly for cargo-check, but also for additional feature checks
    //
    if matches!(version_meta().map(|v| v.channel), Ok(Channel::Nightly)) {
        println!("cargo:rustc-cfg=nightly");
    }
}

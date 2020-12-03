#![allow(clippy::single_match)]

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS")
        .expect("CARGO_CFG_TARGET_OS should always be set by the cargo build env");
    match target_os.as_str() {
        "macos" => println!("cargo:rustc-link-lib=framework=Security"),
        _ => (),
    }
}

use std::{ffi::OsStr, path::PathBuf};

const SRC: &str = "src/bpf/prog.bpf.c";
const HDR: &str = "src/bpf/common.h";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")
       .expect("OUT_DIR must be set in build script"));

    libbpf_cargo::SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            OsStr::new("src/bpf/vmlinux/")
        ])
        .build_and_generate(out_dir.join("prog.bpf.rs"))
        .unwrap();

    bindgen::Builder::default()
            .header(HDR)
            .clang_args(["-I", "src/bpf/vmlinux"])
            .allowlist_type("scap_msg")
            .generate()
            .expect("Unable to generate Rust bindings to common.h")
            .write_to_file(out_dir.join("common.rs"))
            .expect("Couldn't write bindings");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={HDR}");
}

#![allow(clippy::expect_used)] // Build scripts must panic on failure

fn main() {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        linux_ebpf_build();
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn linux_ebpf_build() {
    use std::path::PathBuf;

    let src = PathBuf::from("src/bpf/prxsd.bpf.c");
    if !src.exists() {
        panic!("BPF source not found: {}", src.display());
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let skel_path = out_dir.join("prxsd.skel.rs");

    libbpf_cargo::SkeletonBuilder::new()
        .source(&src)
        .build_and_generate(&skel_path)
        .expect("failed to build and generate BPF skeleton");

    println!("cargo:rerun-if-changed=src/bpf/prxsd.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/prxsd.h");
}

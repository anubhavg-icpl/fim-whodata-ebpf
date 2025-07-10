use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    
    // Copy eBPF object file to output directory for inclusion
    let ebpf_obj = "target/bpfel-unknown-none/release/fim-whodata-ebpf";
    if std::path::Path::new(ebpf_obj).exists() {
        std::fs::copy(ebpf_obj, out_dir.join("fim-whodata-ebpf.o"))
            .expect("Failed to copy eBPF object file");
    }
    
    println!("cargo:rerun-if-changed=fim-whodata-ebpf-bpf/src");
    println!("cargo:rerun-if-changed=fim-whodata-ebpf-common/src");
}
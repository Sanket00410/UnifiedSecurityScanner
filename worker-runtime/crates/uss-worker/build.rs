use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("contracts")
        .join("proto");
    let proto_file = proto_root.join("worker").join("v1").join("worker.proto");

    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-changed={}", proto_file.display());

    if env::var_os("PROTOC").is_none() {
        let default_protoc = if cfg!(windows) {
            PathBuf::from(r"C:\Tools\protoc-31.1\bin\protoc.exe")
        } else {
            PathBuf::from("/usr/bin/protoc")
        };

        if default_protoc.exists() {
            env::set_var("PROTOC", default_protoc);
        }
    }

    tonic_build::configure()
        .build_server(true)
        .compile_protos(&[proto_file], &[proto_root])?;

    Ok(())
}

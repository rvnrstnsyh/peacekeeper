use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
  let crate_root: PathBuf = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
  let proto_root: PathBuf = crate_root.join("..").join("proto").join("v0");
  let proto_file: PathBuf = proto_root.join("contract.proto");
  let out_dir: PathBuf = PathBuf::from(env::var("OUT_DIR").unwrap());

  if !proto_file.exists() {
    panic!("proto file not found: {}", proto_file.display());
  }
  println!("cargo:rerun-if-changed={}", proto_file.display());

  tonic_prost_build::configure()
    .file_descriptor_set_path(out_dir.join("reflection_descriptor.bin"))
    .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
    .build_server(true)
    .build_client(false)
    .compile_protos(&[proto_file], &[proto_root])?;

  return Ok(());
}

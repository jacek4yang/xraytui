//! Generates the Xray gRPC client from the vendored protobuf files.
//!
//! The `.proto` files are committed under `vendor/xray-proto` at a pinned tag, so
//! an ordinary build never fetches anything from the network. `protoc` must be on
//! `PATH`; the build script fails with an actionable message when it is not.

use std::path::{Path, PathBuf};

const PROTOS: &[&str] = &[
    "app/proxyman/command/command.proto",
    "app/router/command/command.proto",
    "app/stats/command/command.proto",
    "app/log/command/config.proto",
];

fn main() {
    let manifest = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("vendor/xray-proto"))
        .expect("crate lives two levels below the workspace root");

    if !root.is_dir() {
        panic!(
            "vendored protobuf directory {} is missing; it is committed to the repository and \
             should never need to be downloaded",
            root.display()
        );
    }

    println!("cargo:rerun-if-changed={}", root.display());
    for proto in PROTOS {
        println!("cargo:rerun-if-changed={}", root.join(proto).display());
    }

    let paths: Vec<PathBuf> = PROTOS.iter().map(|p| root.join(p)).collect();
    for path in &paths {
        assert!(
            path.is_file(),
            "vendored protobuf {} is missing",
            path.display()
        );
    }

    if let Err(error) = tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&paths, &[root])
    {
        panic!(
            "failed to compile vendored Xray protobufs: {error}\n\
             `protoc` must be installed and on PATH (package `protobuf-compiler` on Debian/Ubuntu, \
             `protobuf` on Arch)."
        );
    }
}

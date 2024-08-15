use std::path::PathBuf;

use cmake::Config;

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=llvm/CMakeLists.txt");
    println!("cargo:rerun-if-changed=llvm/Shellcode.cpp");

    let llvm_dir = PathBuf::from(CARGO_MANIFEST_DIR).join("llvm");
    Config::new(llvm_dir)
        .define("CMAKE_BUILD_TYPE", "Debug")
        .build();
}

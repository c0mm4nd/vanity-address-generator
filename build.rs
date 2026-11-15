//! Compiles the CUDA kernel and links it into the binary during
//! `cargo build --features cuda`.
//!
//! CPU-only builds return immediately and never require the CUDA toolkit. With
//! the feature enabled, `cuda/vanity.cu` is compiled to an object file and linked
//! statically, so the resulting `vag` executable is self-contained: no shared
//! library, no runtime path lookup and no ABI negotiation.
//!
//! Set `VAG_CUDA_FIELD_TEST=1` to additionally build `libvag_cuda_test.so`, used by
//! `tests/cuda_field.py` as a ctypes oracle against Python big integers.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    for path in ["cuda/vanity.cu", "cuda/field_test.cu"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in [
        "NVCC",
        "CUDA_ARCH",
        "CUDA_MAX_REGISTERS",
        "VAG_CUDA_FIELD_TEST",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    if env::var_os("CARGO_FEATURE_CUDA").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let nvcc = locate_nvcc();
    let arch = env::var("CUDA_ARCH").unwrap_or_else(|_| "compute_86".into());
    let toolkit = cuda_library_dir(&nvcc);

    // Device code plus its host-side entry points. The object is archived rather
    // than passed with `rustc-link-arg` so the linker sees it before the static
    // CUDA runtime it depends on.
    let object = out_dir.join("vanity.o");
    compile(&nvcc, "cuda/vanity.cu", &object, &arch, false);
    let archive = out_dir.join("libvag_cuda.a");
    let status = Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("cannot run ar; install binutils");
    assert!(
        status.success(),
        "ar failed to archive {}",
        object.display()
    );

    // Static CUDA runtime keeps the executable independent of libcudart at run time.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-search=native={}", toolkit.display());
    println!("cargo:rustc-link-lib=static=vag_cuda");
    println!("cargo:rustc-link-lib=static=cudart_static");
    for library in ["stdc++", "rt", "pthread", "dl"] {
        println!("cargo:rustc-link-lib=dylib={library}");
    }

    // Test-only shared library for the Python field-arithmetic oracle.
    if env::var_os("VAG_CUDA_FIELD_TEST").is_some() {
        // out -> <hash> -> vag -> build -> <profile>
        let profile_dir = out_dir
            .ancestors()
            .nth(4)
            .expect("OUT_DIR layout is target/<profile>/build/<pkg>/<hash>/out");
        let shared = out_dir.join("libvag_cuda_test.so");
        compile(&nvcc, "cuda/field_test.cu", &shared, &arch, true);
        std::fs::copy(&shared, profile_dir.join("libvag_cuda_test.so"))
            .expect("cannot place libvag_cuda_test.so beside the binary");
    }
}

/// Honour `NVCC`, then `nvcc` on `PATH`, then the usual toolkit location.
fn locate_nvcc() -> PathBuf {
    if let Some(path) = env::var_os("NVCC") {
        return PathBuf::from(path);
    }
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join("nvcc");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("/usr/local/cuda/bin/nvcc")
}

/// Derive `<toolkit>/lib64` from the compiler location, falling back to the default.
fn cuda_library_dir(nvcc: &Path) -> PathBuf {
    let mut candidates = Vec::new();
    if let Some(root) = nvcc.parent().and_then(Path::parent) {
        candidates.push(root.join("lib64"));
        candidates.push(root.join("lib"));
    }
    candidates
        .into_iter()
        .find(|path| path.join("libcudart_static.a").is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/local/cuda/lib64"))
}

fn compile(nvcc: &Path, source: &str, output: &Path, arch: &str, shared: bool) {
    let mut command = Command::new(nvcc);
    command
        .args(["-O3", "-std=c++17", &format!("-arch={arch}")])
        .args(["-Xcompiler=-fPIC", "-DNDEBUG"]);
    if shared {
        command.args(["-shared", "-Xcompiler=-fPIC"]);
    } else {
        command.arg("-c");
    }
    command.arg(source).arg("-o").arg(output);
    if let Some(registers) = env::var_os("CUDA_MAX_REGISTERS") {
        command.arg(format!("--maxrregcount={}", registers.to_string_lossy()));
    }
    let result = command.output().unwrap_or_else(|e| {
        panic!(
            "cannot run {} ({e}); install the CUDA toolkit, set NVCC, or build without --features cuda",
            nvcc.display()
        )
    });
    if !result.status.success() {
        panic!(
            "nvcc failed for {source} with {arch}:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

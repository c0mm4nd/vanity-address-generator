# CUDA backend

The optional CUDA backend keeps secp256k1 public points on the GPU and copies back only
plausible matches. Enabling the `cuda` feature compiles the kernel during `cargo build`
and links it—together with the static CUDA runtime—directly into the `vag` executable.

CUDA currently supports **ETH and TRON in private-key mode**. Solana, Bitcoin and
mnemonic derivation remain CPU-only. There is no silent CPU fallback: if no GPU is
present, the chain/mode is unsupported, or a driver call fails, the run exits instead of
continuing on the CPU.

## Building

Requirements: an NVIDIA GPU, a CUDA toolkit providing `nvcc`, and a Rust toolchain.

```bash
cargo build --release --locked --features cuda
./target/release/vag --gpu --mode private-key -c eth -r '^0xabcd.*1234$' --gpu-platform 0
```

`build.rs` invokes `nvcc` and links `cuda/vanity.cu` plus `libcudart_static.a` into the
binary, so the build produces a single self-contained executable: nothing to copy
alongside it, no runtime library lookup, and no ABI negotiation. CPU-only builds return
from `build.rs` immediately and never require the CUDA toolkit.

`nvcc` is taken from `NVCC` if set, otherwise from `PATH`, otherwise from
`/usr/local/cuda/bin/nvcc`. Build-time environment variables:

| Variable | Meaning |
|---|---|
| `NVCC` | Path to the CUDA compiler |
| `CUDA_ARCH` | `-arch` target, default `compute_86` |
| `CUDA_MAX_REGISTERS` | Optional `--maxrregcount` value |
| `VAG_CUDA_FIELD_TEST` | Also build `libvag_cuda_test.so` for `tests/cuda_field.py` |

The default `CUDA_ARCH=compute_86` emits PTX for compute capability 8.6 and newer, which
also JITs on Blackwell. For a native build use the matching `sm_` target—`sm_86` on an
RTX 3090, `sm_120` on an RTX PRO 6000 Blackwell with a toolkit that supports it:

```bash
CUDA_ARCH=sm_86 cargo build --release --locked --features cuda
```

The executable no longer needs a matching external library: kernel and runtime are part
of it. Rebuilding after changing `cuda/vanity.cu` is automatic.

## Selecting devices and lanes

`--gpu-platform` chooses one CUDA device by index (not an OpenCL platform). To use
several GPUs, run one process per device with different indices.

`--gpu-lanes` defaults to 16384 (2,097,152 candidates per batch) and accepts 1–65536.
More lanes can improve GPU utilization at the cost of memory and latency. The tuned
RTX 3090 selective ETH search uses 65536 lanes:

```bash
CUDA_ARCH=sm_86 CUDA_MAX_REGISTERS=160 cargo build --release --locked --features cuda
./target/release/vag --gpu --mode private-key --gpu-lanes 65536 \
  --case -r '^0xCCCCCCCCCC'
```

`CUDA_MAX_REGISTERS` is optional. It trades register use against occupancy and spills; a
smaller limit is not necessarily faster, and leaving it unset uses the compiler default on
untested GPUs.

## Design

Each lane stores the center `C = P + 64G` of its next batch. The pairs `C+jG` and `C-jG`
share a denominator, so 65 denominators (including the next-center update) suffice for
128 candidates instead of 128. The exported offsets are still exactly `P+G` through
`P+128G`; the center is candidate 64. Seeding shifts public points on the GPU once,
without changing the host private keys. Both signs reuse one hash body, with direct word
packing and fully unrolled Keccak rounds.

The kernel amortizes one field inversion across 128 candidates per lane. Inversion uses a
fixed addition chain for `p-2` (255 squares and 15 other multiplications, previously 256
squares and 249 other multiplications). Private scalars remain on the CPU. Initialization
uses up to 16 CPU workers.

## Matching and correctness

ETH patterns such as `^0xabcd`, `1234$` and `^0xabcd.*1234$` use GPU nibble filters and
copy back only possible matches; full regex matching (including EIP-55 case) still runs on
the CPU. Other regex forms, and all TRON patterns, copy every address hash back for CPU
encoding and matching, which is significantly slower. Use a literal ETH prefix or suffix
when maximum throughput matters.

Every saved GPU match is recomputed from its private key on the CPU. Each run first
cross-checks CUDA against CPU results, including curve boundary cases. After a saved match
in `--looping` mode, all lane seeds are replaced before another wallet is produced, so
related keys from a search sequence are never exported together.

## Testing

The device-side field arithmetic is validated against Python big integers by building the
oracle library and running the script:

```bash
CUDA_ARCH=sm_120 VAG_CUDA_FIELD_TEST=1 cargo build --release --features cuda
python3 tests/cuda_field.py
```

Rust-side CUDA tests, including the device/CPU comparison suites, are ignored tests that
must run on a GPU host. The kernel is linked into the test binary, so no environment
variable or external library is needed:

```bash
CUDA_ARCH=sm_120 cargo test --release --features cuda -- --ignored --test-threads=1
python3 tests/cli.py --gpu
```

On a host with Compute Sanitizer, run the computation test under memcheck and initcheck.
The invalid-device test deliberately causes a CUDA API error and is run separately from
sanitizer checks:

```bash
CUDA_ARCH=sm_120 cargo test --release --features cuda --no-run
# Use the test executable printed by cargo in place of TEST_BINARY below:
compute-sanitizer --tool memcheck --error-exitcode 99 \
  TEST_BINARY cuda_matches_cpu --ignored --nocapture --test-threads=1
# Repeat with --tool initcheck to check uninitialized device-memory reads.
```

See [Benchmarks and validation](benchmarks.md) for measured throughput, the full
validation coverage and tuning history.

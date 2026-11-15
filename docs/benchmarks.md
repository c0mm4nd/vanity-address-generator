# Benchmarks and validation

Measured throughput for the CPU and CUDA backends, the CUDA validation suite, and the
tuning history behind the current kernel. These are single measurements on shared
machines, not guarantees.

Rates include seed setup, transfers and matching. CUDA initialization and the mandatory
startup self-test are excluded. CPU benchmarks sum completed work across workers; CUDA
benchmarks use the device-reported count of valid candidates (excluding the point at
infinity) and also report kernel time measured by CUDA events.

## Blackwell, statically linked binary (2026-11-15)

After moving the kernel from a runtime-loaded shared library into the executable, the
`sm_120` build was revalidated on an RTX PRO 6000 Blackwell Max-Q. A 10-second
`--gpu-lanes 65536` benchmark with the case-sensitive `^0xCCCCCCCCCC` filter measured
**2.49 billion addresses/s** overall (9.461 s of device kernel time, 24,897,388,544
candidates). The full CUDA/CPU comparison suite, the 16868-vector field oracle
(5 operations each), CPU and GPU CLI tests and Clippy all passed on that build.

The higher rate than the figures below comes from the GPU and instruction set
(`sm_120` versus `sm_86` on an RTX 3090), not from the linkage change. Those earlier
measurements are kept as recorded history.

## Current kernel (2026-10-25)

The current kernel uses symmetric point pairs, one shared hash body, direct coordinate
packing and fully unrolled Keccak rounds. Six alternating 20-second runs on an otherwise
idle RTX 3090 (GPU 4) compared it with the previous addition-chain kernel. Both used
65536 lanes, a register limit of 160, the same Rust executable and the case-sensitive
`^0xCCCCCCCCCC` filter. The four search GPUs stayed running.

| Kernel | Runs | Mean addresses/s |
|---|---:|---:|
| Previous addition-chain kernel | 3 | 1,068,286,203 |
| Current symmetric-pair / Keccak kernel | 3 | 1,203,309,822 |

This is a further **12.6%** improvement at unchanged launch settings. New runs ranged
from 1.199 to 1.211 billion addresses/s. Compiler-reported per-thread stack space fell
from 4416 to 2176 bytes. Limits of 128/168 registers did not establish an improvement
over 160 in screening; more aggressively combining separate hash bodies increased spills
and failed to deliver the same performance.

The exact final library passed the 4580 field vectors, all 147456 boundary positions,
filtered completeness, 256 consecutive batches, full buffers through 65536 lanes and the
CPU/CUDA CLI tests before deployment. Rust tests, Clippy and format checks also passed.
This iteration was validated on RTX 3090; the Blackwell and Compute Sanitizer results
below belong to earlier kernel builds.

## First tuning pass

The first pass used an otherwise idle RTX 3090 (physical GPU 4 on a shared 4-GPU host)
while the four search GPUs continued running. Seven alternating 20-second runs used the actual
case-sensitive `^0xCCCCCCCCCC` filter and the same Rust executable. The GPU was already
warm; clocks and temperature were recorded.

| CUDA configuration | Lanes | Runs | Mean addresses/s |
|---|---:|---:|---:|
| Original binary-exponent inversion, compiler register default | 32768 | 2 | 885,086,764 |
| Same original kernel, more lanes | 65536 | 2 | 1,002,181,468 |
| Addition-chain inversion, register limit 160 | 65536 | 3 | 1,063,566,343 |

The combined improvement was **20.2%** against the previous search configuration; the
kernel/register changes contributed **6.1%** at equal lane counts. Optimized runs ranged
from 1.058 to 1.071 billion addresses/s. Limits of 96 and 128 registers, alternative
block sizes, a non-inlined inversion and symmetric squaring did not beat the selected
configuration in the short screening runs. Only the addition chain and optional
register-limit build setting were retained; block size and ABI remain unchanged. These
results do not establish a global optimum or predict performance on other GPU
architectures.

The final `sm_86`, register-limit-160 library passed all 4580 field vectors, the full
CUDA/CPU comparison suite (including 256 consecutive batches and 65536 lanes), and
CPU/CUDA CLI tests on GPU 4 before replacing the four search workers.

## Baseline CPU and GPU rates

ETH measurements, release builds. CPU figures use 5-second runs; the RTX 3090 CUDA figure
uses a 10-second run, 32768 lanes and `^0x000000`, with encoding/regex matching included
and candidate counts returned by the GPU. GPU initialization and startup verification are
excluded; initial seed setup is included.

| Machine / mode | Addresses per second |
|---|---:|
| AMD EPYC 7K62, original mnemonic mode, 1 CPU worker | ~700 |
| Same CPU, `--mode private-key`, 1 worker | 36,491 |
| Same CPU, `--mode private-key`, 8 workers | 290,108 |
| Shared GPU host, **one** RTX 3090 (device 0), CUDA private-key | 894,892,218 |
| Workstation, RTX PRO 6000 Blackwell Max-Q, CUDA private-key | 2,489,089,358 |

The roughly 52x CPU improvement comes primarily from changing recovery mode:
`--mode private-key` omits BIP39 seed derivation and HD derivation. Keeping mnemonic mode
retains approximately the original throughput. GPU support previously consisted of a
panic-only placeholder, so there is no prior CUDA throughput to compare.

The revalidated RTX 3090 run checked **8,950,644,736** valid candidates in
**10.002 seconds**, with **9.873 seconds** of device kernel time and 551 matching
candidates. It saved no wallets. The previously reported Blackwell throughput
(1.846 billion/s) came from the earlier build; that rate is not presented as a
measurement of the current build because the GPU was busy during revalidation.

Remote Rust binaries used `target-cpu=x86-64-v3`; CUDA used `sm_86` on RTX 3090 and
`compute_86` PTX on Blackwell. The default lane count remains 16384 to reduce memory use
and latency. A separate generation test also passed on RTX 3090 device 1.

These GPU rates apply to selective ETH hex filters. An earlier 4096-lane RTX 3090 run
transferring **every** hash with `^0x` measured only ~16.8 million addresses/s:
CPU formatting/regex and transfers become the limit. TRON uses this CPU fallback path for
Base58 encoding and matching, so ETH's headline throughput does not apply to TRON.

## Validation suite

The CUDA validation suite checks:

- **4580 field vectors × 4 operations** (addition, subtraction, multiplication,
  inversion), comparing the production GPU code against Python big integers. Inputs cover
  zero, values near the field modulus, limb carries and fixed-seed random values. Build
  with `VAG_CUDA_FIELD_TEST=1` and run `python3 tests/cuda_field.py`; no extra Python
  packages are needed.
- **49536 candidate positions × 5 filters**, comparing all returned values and checking
  for missing or extra matches against CPU results.
- **256 consecutive batches / 4,227,071 valid candidates**, checking counts and duplicate
  indices throughout, with per-lane endpoint and rotating interior samples checked against
  a separate pure-Rust secp256k1 implementation.
- **147456 boundary candidate positions**, using 384 positive/negative small scalars
  across three batches. Every returned hash is independently checked, including
  center/next-center infinity, doubling, cancellation, scalar wraparound and completeness
  of the exported offsets.
- Lane counts **1, 127, 128, 129, 2048, 16384, 32768 and 65536** with every candidate
  returned: full buffer counts/indices plus independent CPU checks of each lane's first
  and last candidate (14,991,488 candidate positions in total).
- Independent filters for interleaved CUDA instances, reseeding, undersized host buffer
  rejection without state advancement, and invalid device handling.
- End-to-end wallet generation, EIP-55 case matching, general-regex fallback, looping, no
  wallet output during benchmarks, and agreement between returned match counts, device
  counts and printed rates.

Fixed seeds in tests are separate from the OS-seeded wallet RNG. Every production run
retains the startup CPU/GPU cross-check and CPU verification of saved matches. Old CUDA
libraries without ABI version metadata are rejected before computation.

Field-arithmetic checks, expanded CPU/GPU comparisons and end-to-end CLI tests passed on
both GPU machines. CPU tests, both Rust feature configurations and Clippy also passed.

On Blackwell, Compute Sanitizer **memcheck and initcheck both reported 0 errors** for the
expanded computation suite. Deliberate invalid-device handling was tested separately. The
RTX 3090 host did not have Compute Sanitizer installed.

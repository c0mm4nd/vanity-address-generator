# CLI reference and usage

This document covers building the generator, recovery modes, every command-line option,
regex behavior, examples and output formats. For the CUDA backend see
[CUDA backend](cuda.md); for measured performance see [Benchmarks](benchmarks.md).

## Building

CPU builds require only a stable Rust toolchain; CUDA and OpenCL are not needed.

```bash
cargo build --release --locked
```

The repository enables `target-cpu=native` in `.cargo/config.toml`, which is fastest on
the build machine. When moving a binary between different CPUs, target a shared
instruction set instead—for example x86-64-v3:

```bash
RUSTFLAGS='-C target-cpu=x86-64-v3' cargo build --release --locked
```

For the GPU backend, add the `cuda` feature and build the shared library; see
[CUDA backend](cuda.md#building).

## Recovery modes

`--mode` selects how candidates are generated:

| Mode | Flag | Recovery material | Notes |
|---|---|---|---|
| Mnemonic (default) | `--mode mnemonic` | 12- or 24-word BIP39 mnemonic | Original behavior; slower because each candidate runs PBKDF2 and HD derivation |
| Private key | `--mode private-key` | Raw private key only | Generates independent keys from an OS-seeded CSPRNG; substantially faster |

In private-key mode the saved `mnemonic` field is an empty string—recovery uses the
private key, not a mnemonic. Bitcoin addresses in this mode use compressed public keys
and witness version 0 for P2WPKH.

## Supported chains

| Flag | Network / format | Derivation path (mnemonic mode) |
|---|---|---|
| `eth` | Ethereum, `0x` + 20 bytes | `m/44'/60'/0'/0/0` |
| `btc`, `btc-p2pkh` | Bitcoin P2PKH (`1...`) | `m/44'/0'/0'/0/0` |
| `btc-p2sh` | Bitcoin P2SH (`3...`) | `m/49'/0'/0'/0/0` |
| `btc-bech32` | Bitcoin SegWit v0, P2WPKH (`bc1q...`) | `m/84'/0'/0'/0/0` |
| `sol` | Solana Base58 public key | `m/44'/501'/0'/0'` |
| `trx`, `tron` | TRON Base58Check (`T...`) | `m/44'/60'/0'/0/0` (Ethereum path) |

## Options

| Option | Meaning |
|---|---|
| `-r, --regex` | Address regex; required except in benchmark mode |
| `-c, --chain` | `eth`, `btc`/`btc-p2pkh`, `btc-p2sh`, `btc-bech32`, `sol`, `trx`/`tron` |
| `--mode <MODE>` | `mnemonic` (default) or `private-key` (no mnemonic) |
| `-t, --threads` | CPU search workers; defaults to the available CPU count |
| `-w, --words` | Mnemonic word count: 12 (default) or 24; mnemonic mode only |
| `-C, --case` | Case-sensitive regex; Ethereum output uses EIP-55 checksums |
| `-l, --looping` | Continue producing wallets after a match |
| `-b, --benchmark` | Timed throughput measurement; never saves wallets |
| `--benchmark-seconds` | Benchmark duration, default 10 seconds |
| `--gpu` | Use CUDA; requires `--mode private-key` and the `cuda` feature |
| `--gpu-platform` | CUDA device index, default 0 |
| `--gpu-lanes` | GPU lane count, default 16384 |
| `--cuda-library` | Shared library path; defaults to beside the executable |
| `-W, --webhook` | Reserved option; webhook delivery is not implemented |

`--gpu-platform` selects one CUDA device by index (it is not an OpenCL platform). To use
several GPUs, run one process per device with different indices.

## Regex behavior

- Matching is case-insensitive by default; `-C, --case` enables case-sensitive matching.
  With `--case`, Ethereum addresses are formatted with EIP-55 checksums before matching.
- Whitespace inside the regex is ignored.
- Invalid regex syntax and zero worker counts are rejected before workers start.
- Matching runs against the fully formatted address. For CUDA searches, ETH patterns
  that are literal prefixes/suffixes of hex digits are filtered on the GPU first; full
  regex matching still runs on the CPU.

## Examples

```bash
# Default mnemonic mode
./target/release/vag -c eth -r '^0xabcd' -w 12

# Fast private-key search with 8 CPU workers
./target/release/vag --mode private-key -c eth -r '^0xabcd' -t 8

# Case-sensitive Ethereum prefix with EIP-55 output
./target/release/vag --mode private-key -C -r '^0xCCCCCCCCCC'

# Suffix and combined patterns
./target/release/vag --mode private-key -c eth -r '1234$'
./target/release/vag --mode private-key -c eth -r '^0xabcd.*1234$'

# Other chains in private-key mode
./target/release/vag --mode private-key -c btc-bech32 -r '^bc1qabc'
./target/release/vag --mode private-key -c sol -r '^ABC'
./target/release/vag --mode private-key -c trx -r '^TABC'

# Keep searching and saving after the first match
./target/release/vag --mode private-key -c eth -r '^0xabcd' -l

# GPU search (see docs/cuda.md)
./target/release/vag --gpu --mode private-key -c eth -r '^0xabcd.*1234$' --gpu-platform 0
```

## Output format

Every match is printed and written to `<address>.json` in the working directory
(characters `/` and `:` in the address are replaced with `_`):

```json
{
  "address": "0xabcd0123456789abcdef0123456789abcdef0123",
  "private_key": "0x...",
  "mnemonic": "word1 word2 ... word12",
  "duration_seconds": 12,
  "duration_human": "12.34s",
  "timestamp": "2026-10-25T09:00:00+00:00",
  "chain_type": "eth"
}
```

| Chain | `private_key` format |
|---|---|
| Ethereum, TRON | 32-byte hex string |
| Bitcoin (all formats) | 32-byte hex string |
| Solana | Base58-encoded 64-byte keypair (32-byte secret + 32-byte public) |

In private-key mode `mnemonic` is `""`; otherwise it contains the BIP39 mnemonic used to
derive the key. In `--looping` mode every match is saved until the process is stopped;
without it the process exits after the first match.

## Benchmarks

Benchmark mode reports completed candidates per second and never writes wallet files.
Use the same regex and worker count for CPU comparisons:

```bash
# Mnemonic mode, one worker
./target/release/vag -b --benchmark-seconds 10 -t 1 -r '^0x000000'

# Private-key mode, one and eight workers
./target/release/vag --mode private-key -b --benchmark-seconds 10 -t 1 -r '^0x000000'
./target/release/vag --mode private-key -b --benchmark-seconds 10 -t 8 -r '^0x000000'

# GPU benchmark, including seed setup, transfers and matching
./target/release/vag --gpu --mode private-key -b --benchmark-seconds 10 \
  --gpu-lanes 32768 -r '^0x000000'
```

CPU benchmarks sum completed work across workers. CUDA benchmarks use the device-reported
count of valid candidates (excluding the point at infinity) and also report kernel time
measured by CUDA events. A final CPU group of 64 or a GPU batch may extend the requested
duration slightly. Broad matching patterns do not produce wallet files during a benchmark.

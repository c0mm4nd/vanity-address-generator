# Vanity Address Generator

Generate Ethereum, Bitcoin, Solana and TRON vanity addresses with multi-threaded CPU
workers or an optional CUDA backend.

[Quick start](#quick-start) · [CLI reference](docs/usage.md) · [CUDA backend](docs/cuda.md) ·
[Benchmarks](docs/benchmarks.md)

## Features

- **Multi-threaded CPU search** on every Rust-supported platform.
- **CUDA backend** for ETH and TRON searches, reaching about 1.2 billion addresses/s on
  an RTX 3090 with selective hex filters.
- **Two recovery modes** — BIP39 mnemonic (default) or faster independent private keys.
- **Case-sensitive matching**, including EIP-55 checksummed Ethereum output.
- **JSON results** containing the address, private material, duration and timestamp.
- **Looping and benchmark modes** for continuous search and throughput measurement.

## Quick start

Requires a stable Rust toolchain.

```bash
cargo build --release --locked
./target/release/vag -c eth -r '^0xabcd' -t 8
```

By default each candidate is a fresh BIP39 mnemonic. For a much faster search that
produces independent random keys instead, add `--mode private-key`:

```bash
./target/release/vag --mode private-key -c eth -r '^0xabcd' -t 8
```

Matches are printed and saved as `<address>.json` in the current directory:

```json
{
  "address": "0xabcd0123...",
  "private_key": "0x...",
  "mnemonic": "word1 word2 ...",
  "duration_seconds": 12,
  "duration_human": "12.34s",
  "timestamp": "2026-10-25T09:00:00+00:00",
  "chain_type": "eth"
}
```

In private-key mode `mnemonic` is empty. ETH, TRON and Bitcoin export 32-byte hex
private keys; Solana exports a Base58-encoded 64-byte keypair. Recovery formats and
per-chain details are in the [CLI reference](docs/usage.md#output-format).

## Supported chains

| Flag | Network / format | Example address |
|---|---|---|
| `eth` | Ethereum (EIP-55 with `--case`) | `0xabcd...` |
| `btc`, `btc-p2pkh` | Bitcoin P2PKH | `1...` |
| `btc-p2sh` | Bitcoin P2SH | `3...` |
| `btc-bech32` | Bitcoin SegWit v0 (P2WPKH) | `bc1q...` |
| `sol` | Solana | `ABC...` |
| `trx`, `tron` | TRON | `T...` |

## CUDA search (NVIDIA GPUs)

CUDA supports **ETH and TRON in private-key mode**. Solana, Bitcoin and mnemonic
derivation remain CPU-only.

```bash
cargo build --release --locked --features cuda
./target/release/vag --gpu --mode private-key -c eth -r '^0xabcd.*1234$'
```

The `cuda` feature compiles `cuda/vanity.cu` and links the kernel and the static CUDA
runtime into `vag` itself, so the result is a single self-contained executable—no
shared library to ship, no runtime path lookup. CPU-only builds never invoke `nvcc`.
Set `CUDA_ARCH` at build time for a native target (`CUDA_ARCH=sm_120`, for example).

See the [CUDA backend guide](docs/cuda.md) for architecture-specific builds, register
tuning, lane configuration, runtime checks and limitations.

## Documentation

- [CLI reference and usage](docs/usage.md) — all options, regex rules, examples, output
- [CUDA backend](docs/cuda.md) — building, tuning, design and testing
- [Benchmarks and validation](docs/benchmarks.md) — measured throughput and test coverage

## Development

```bash
cargo test --locked
cargo clippy --all-targets --features cuda -- -D warnings
python3 tests/cli.py

# On a GPU host, with the kernel linked in by the cuda feature:
cargo test --release --features cuda -- --ignored --test-threads=1
VAG_CUDA_FIELD_TEST=1 cargo build --release --features cuda && python3 tests/cuda_field.py
```

The repository sets `target-cpu=native` in `.cargo/config.toml`. For binaries that
must run on other machines, build for a shared instruction set—see
[Building](docs/usage.md#building).

## Security

Generated JSON files contain spendable private keys. Store them encrypted, restrict
file permissions, and run the generator on a trusted offline machine when possible.

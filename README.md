# Vanity Address Generator

> Generate personalized blockchain addresses with your unique preferences

A high-performance, multi-threaded tool for generating vanity addresses across multiple blockchains. Supports Ethereum, Bitcoin (P2PKH, P2SH, Bech32), and Solana.

## Features

- **Multi-blockchain support**: Ethereum, Bitcoin (multiple formats), and Solana addresses
- **High-performance**: Multi-threaded architecture for maximum speed
- **Pattern matching**: Powerful regex-based pattern matching
- **Mnemonic-based**: Generates standard BIP39 mnemonics for wallet recovery
- **Webhook integration**: Send results to webhooks for notifications
- **Performance metrics**: Real-time hashrate display

## Requirements

- Install Rust (https://www.rust-lang.org/learn/get-started)

## Installation

```bash
# Clone the repository
git clone https://github.com/c0mm4nd/vanity-address-generator

# Build the project
cd vanity-address-generator
cargo build --release
```

## Usage

```bash
./target/release/vag --help
```

### Basic Examples

Generate an Ethereum address with a specific pattern:
```bash
./target/release/vag -r "^0xabcd.*" -c eth
```

Generate a Bitcoin address with a specific pattern:
```bash
./target/release/vag -r "^1abc.*" -c btc
```

Generate a Solana address with a specific pattern:
```bash
./target/release/vag -r "^ABC.*" -c sol
```

### Command Line Options

- `-r, --regex <PATTERN>`: Regular expression pattern to match addresses
- `-c, --chain <CHAIN>`: Blockchain to generate address for [default: eth] [possible values: eth, btc, btc-p2pkh, btc-p2sh, btc-bech32, sol]
- `-t, --threads <THREADS>`: Number of threads to use [default: number of CPU cores]
- `-w, --words <WORDS>`: Mnemonic word count (12 or 24) [default: mixed - some threads use 12, others use 24]
- `-W, --webhook <URL>`: Webhook URL to send results to
- `-b, --benchmark`: Enable benchmarking mode
- `--gpu`: Use GPU acceleration (not fully implemented)
- `--gpu-platform <PLATFORM>`: Select GPU platform (not fully implemented)
- `-h, --help`: Print help information
- `-V, --version`: Print version information

## Address Types

| Chain Option | Description | Address Format Example |
|-------------|-------------|------------------------|
| eth | Ethereum | 0x71C7656EC7ab88b098defB751B7401B5f6d8976F |
| btc, btc-p2pkh | Bitcoin P2PKH | 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 |
| btc-p2sh | Bitcoin P2SH | 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy |
| btc-bech32 | Bitcoin Bech32 | bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq |
| sol | Solana | DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK |

## Security Notes

- Bitcoin addresses are designed for single-use. Vanity addresses are not recommended for Bitcoin due to security practices that discourage address reuse.
- Always keep your mnemonic phrases secure. They provide full control over the generated wallets.

## Performance Considerations

- The tool will use all available CPU cores by default
- Performance is displayed in real-time as addresses per second
- For maximum performance, build with `--release` flag

## Development

Contributions are welcome! Feel free to submit pull requests.

## License

[MIT License](LICENSE)

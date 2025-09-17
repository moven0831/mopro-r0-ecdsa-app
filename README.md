# RISC0 + Mopro Example App

Minimal Flutter template for RISC0 zkVM proof generation and verification on mobile devices using Mopro.

## Architecture

```
├── risc0-circuit/          # RISC0 zkVM circuit and host code
│   ├── src/main.rs         # Host program (proof generation)
│   └── methods/guest/      # Guest program (runs in zkVM)
├── mopro-r0-example-app/   # Mopro FFI bindings
│   ├── src/lib.rs          # UniFFI exports for mobile
│   └── flutter/            # Flutter app (cross platforms)
└── Cargo.toml              # Rust workspace configuration
```

## App Demo
Mopro Risc0 Example App demo running live on Pixel 10 Pro. 

<div align="center">

|  |  |
|:-------------------------:|:---------------------:|
| <img src="./assets/img/r0-example-1.jpg" alt="Noir Wallet Connect" width="280"/> | <img src="./assets/img/r0-example-2.jpg" alt="Noir On-Chain Verification" width="280"/> |

</div>

## Prerequisites

Install required tools:

```bash
# Install the latest Mopro CLI
git clone git@github.com:zkmopro/mopro.git
cd cli && cargo install --path .

# Install Flutter SDK
# See: https://flutter.dev/docs/get-started/install

# Verify installation
mopro --version
flutter --version
```

## Quick Start

1. **Clone and setup**:
```bash
git clone git@github.com:zkmopro/mopro-r0-example-app.git
cd mopro-r0-example-app/mopro-r0-example-app
```

2. **Build native bindings**:
```bash
mopro build
```

3. **Update bindings**:
```bash
mopro update
```

6. **Run Flutter app**:
```bash
cd flutter
flutter pub get
flutter run

# Run `flutter emulator` to check available one if you want to run on PC first
```

## Development Commands

### Circuit Development
Currently the risc0 is basic template. You can write your risc0 program in `risc0-circuit/`. More more examples, please refers to [risc0/examples](https://github.com/risc0/risc0/tree/main/examples).

**`risc0-circuit/`**: Contains a risc0 program
- `src/main.rs`: Host code that generates proofs
- `methods/guest/src/main.rs`: Guest code that runs inside zkVM

```bash
# Run RISC0 host program directly
cd risc0-circuit && cargo run

# Run with execution logs
RUST_LOG="[executor]=info" RISC0_DEV_MODE=1 cargo run
```

### Mobile Development
For customizing your risc0 program with Mopro, you can refer to [Mopro Docs](https://zkmopro.org/docs/setup/rust-setup#-customize-the-bindings).

**`mopro-r0-example-app/`**: FFI bindings and mobile integration
- `src/lib.rs`: Exported functions for mobile apps
- `flutter/`: Flutter template

```bash
# Run tests
cargo test      # Rust tests

# Rebuild after Rust changes
mopro build && mopro update
```

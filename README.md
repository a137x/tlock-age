# tlock_age

Decrypt-only timelock cryptography library for [drand](https://drand.love/) networks. Supports BLS12-381 (quicknet/fastnet) and BN254 (evmnet) curves.

Built for deterministic execution environments (Scrypto/WASM smart contracts) where RNG is unavailable.

## Motivation

[Timelock encryption](https://eprint.iacr.org/2023/189) allows encrypting a message such that it can only be decrypted after a specific drand round is reached — when the network publishes the round's BLS signature. The original [tlock](https://github.com/drand/tlock) (Go) and [tlock-rs](https://github.com/nicoritschel/tlock-rs) implementations require randomness for encryption and depend on `std::io` features incompatible with `no_std`/WASM targets.

This library strips out all encryption and non-deterministic (RNG) code, retaining **only decryption and signature verification**. This makes it safe to run inside Scrypto smart contracts on the Radix ledger, where all execution must be deterministic.

## What's Inside

This is a composite library ("Frankenstein crate") that internalizes and modifies several upstream libraries to remove RNG dependencies:

### Embedded Components

| Component | Origin | What Was Changed |
|-----------|--------|-----------------|
| `age` | [str4d/rage](https://github.com/str4d/rage) | Encryption removed. Only `Decryptor`, `Identity` trait, header parsing, and ChaCha20-Poly1305 stream decryption remain. All RNG-dependent code paths removed. |
| `age_core` | [str4d/rage](https://github.com/str4d/rage) (age-core subcrate) | Format parsing and stanza primitives only. Write/serialization paths stripped where they required randomness. |
| `tlock` | [thibmeu/tlock-rs](https://github.com/nicoritschel/tlock-rs) | Decryption only. IBE (Identity-Based Encryption) decrypt with BLS12-381 signatures via arkworks. Encryption functions removed entirely. |
| `kyber` | [drand/kyber](https://github.com/drand/kyber) (Go) | **Byte-for-byte Rust port** of the Go BN254 pairing and IBE implementation. Only the decryption path. This is not a wrapper — it's a manual translation preserving exact arithmetic behavior. |

### Why Not Publish Separate Forks?

The modifications go deep — removing RNG from `age` requires changes in `age_core` primitives, which changes the `Identity` trait contract, which changes how `tlock` implements decryption. Publishing each as a separate fork would mean maintaining 4 crates with tightly coupled modifications. Bundling them is pragmatic: they serve one purpose (tlock decrypt) and change together.

## Supported Curves

| Curve | drand Network | Signature Group | Usage |
|-------|--------------|-----------------|-------|
| BLS12-381 | quicknet, fastnet, mainnet | G1 (48 bytes) or G2 (96 bytes) | Primary — most drand networks |
| BN254 | evmnet | G2 (128 bytes) | Backup — if quicknet stops producing signatures |

Curve detection is automatic via `TlockCurve::from_chain_hash()`.

## API

```rust
use tlock_age::{decrypt, decrypt_header, decrypt_bn254};

// Extract round number and chain hash from an encrypted file header
let header = tlock_age::decrypt_header(reader)?;
// header.round — the drand round needed for decryption
// header.hash  — chain hash identifying the drand network

// Decrypt with a drand signature (BLS12-381 or BN254, detected automatically)
tlock_age::decrypt(
    &mut output,        // writer for plaintext
    input,              // reader for age-encrypted ciphertext
    &chain_hash,        // drand network chain hash
    &signature,         // drand round signature
    None,               // optional precomputed file key
)?;
```

## Features

| Feature | Effect |
|---------|--------|
| `armor` | Enables ASCII-armored input/output (age armor format). Required when ciphertext is stored as text (e.g., in a database). |
| `internal` | Exposes the `internal` module publicly (identity implementations). |

## Usage

```toml
[dependencies]
tlock_age = { git = "https://github.com/a137x/tlock-age", features = ["armor"] }
```

## License

Components derived from rage (age/age_core) are under MIT/Apache-2.0.
Components derived from tlock-rs are under MIT.
The kyber BN254 port follows the original drand/kyber license (Apache-2.0).

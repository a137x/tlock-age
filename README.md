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
| `kyber` | Rust port of [drand/kyber](https://github.com/drand/kyber) (Go) | **Byte-for-byte Rust port** of the Go BN254 pairing and IBE implementation. Only the decryption path. This is not a wrapper — it's a manual translation of the Go source preserving exact arithmetic behavior across all BN254 curve operations (field arithmetic, pairing, point marshaling). |

### Why Not Publish Separate Forks?

The modifications go deep — removing RNG from `age` requires changes in `age_core` primitives, which changes the `Identity` trait contract, which changes how `tlock` implements decryption. Publishing each as a separate fork would mean maintaining 4 crates with tightly coupled modifications. Bundling them is pragmatic: they serve one purpose (tlock decrypt) and change together.

## Precomputed File Key Optimization

This library implements a critical optimization for smart contract environments: **precomputed file key verification**.

### The Problem

Standard tlock decryption has two phases:
1. **IBE decrypt** — recover the 16-byte `file_key` from the tlock stanza using BLS/BN254 pairing operations (extremely expensive, ~millions of CPU cycles)
2. **age decrypt** — use the `file_key` with ChaCha20-Poly1305 to decrypt the actual payload (cheap)

Phase 1 is too expensive to run inside a Scrypto smart contract runtime, which has strict execution cost limits.

### The Solution

The encryption side (see [a137x/tlock-js](https://github.com/a137x/tlock-js), a fork of [drand/tlock-js](https://github.com/drand/tlock-js)) adds an extra field to the age header stanza — the SHA-256 hash of the `file_key`:

```
Standard tlock stanza:
-> tlock <round> <chain_hash>

Modified stanza with file key hash:
-> tlock <round> <chain_hash> <sha256_of_file_key>
```

This enables a two-step workflow:

1. **Off-chain (backend):** Perform the expensive IBE decryption to recover the `file_key`, then send it to the smart contract along with the encrypted message
2. **On-chain (smart contract):** Verify that `SHA-256(supplied_file_key) == file_key_hash` from the stanza header, then skip IBE entirely and jump straight to the cheap ChaCha20-Poly1305 decryption

The contract trusts the precomputed key only if its hash matches what the encryptor committed to in the header. This is secure because:
- The `file_key_hash` is embedded in the encrypted file at encryption time — it cannot be tampered with
- SHA-256 is preimage-resistant — you can't forge a `file_key` that produces the correct hash
- The ChaCha20-Poly1305 AEAD will fail authentication if the wrong key is used

### API with Precomputed Key

```rust
// Full decryption (expensive — runs IBE + ChaCha20)
tlock_age::decrypt(&mut output, input, &chain_hash, &signature, None)?;

// Optimized decryption (cheap — validates hash, skips IBE, runs only ChaCha20)
tlock_age::decrypt(&mut output, input, &chain_hash, &signature, Some(precomputed_file_key))?;
```

The `precomputed_file_key` is a `[u8; 16]` recovered by the backend using `tlock::time_unlock()` or `tlock::bn254::decrypt_bn254()`.

## Supported Curves

| Curve | drand Network | Signature Group | Usage |
|-------|--------------|-----------------|-------|
| BLS12-381 | quicknet, fastnet, mainnet | G1 (48 bytes) or G2 (96 bytes) | Primary — most drand networks |
| BN254 | evmnet | G2 (128 bytes) | Backup — if quicknet stops producing signatures |

Curve detection is automatic via `TlockCurve::from_chain_hash()`.

### BN254 Kyber Port

The `kyber/` module is a direct Rust port of the Go [drand/kyber](https://github.com/drand/kyber) library's BN254 pairing implementation. It includes:

- Full BN254 field arithmetic (`gfp`, `gfp2`, `gfp6`, `gfp12`)
- Optimal Ate pairing (`optate.rs`)
- G1/G2 point operations and marshaling (`point.rs`)
- IBE decryption on BN254 (`kyber/ibe/`)
- Lattice-based operations (`lattice.rs`)

This exists as a fallback: if drand's quicknet (BLS12-381) stops producing signatures, the library can decrypt messages encrypted for drand's evmnet (BN254) instead.

## API

```rust
use tlock_age::{decrypt, decrypt_header, decrypt_bn254};

// Extract round number and chain hash from an encrypted file header
let header = tlock_age::decrypt_header(reader)?;
// header.round — the drand round needed for decryption
// header.hash  — chain hash identifying the drand network

// Decrypt BLS12-381 tlock (quicknet/fastnet)
tlock_age::decrypt(
    &mut output,        // writer for plaintext
    input,              // reader for age-encrypted ciphertext
    &chain_hash,        // drand network chain hash
    &signature,         // drand round signature (G1 48 bytes or G2 96 bytes)
    None,               // optional precomputed file key
)?;

// Decrypt BN254 tlock (evmnet)
tlock_age::decrypt_bn254(
    &mut output,
    input,
    &chain_hash,
    &signature,         // BN254 G2 signature (128 bytes)
    None,
)?;
```

## Features

| Feature | Effect |
|---------|--------|
| `armor` | Enables ASCII-armored input/output (age armor format). Required when ciphertext is stored as text (e.g., in a database). |
| `internal` | Exposes the `internal` module publicly (identity implementations, useful for testing). |

## Usage

```toml
[dependencies]
tlock_age = { git = "https://github.com/a137x/tlock-age", features = ["armor"] }
```

## Companion Libraries

| Library | Purpose |
|---------|---------|
| [a137x/tlock-js](https://github.com/a137x/tlock-js) | JavaScript encryption library (fork of [drand/tlock-js](https://github.com/drand/tlock-js)). Adds `file_key_hash` to the tlock stanza for precomputed key verification. Used by the frontend to encrypt oracle votes. |

## License

Components derived from rage (age/age_core) are under MIT/Apache-2.0.
Components derived from tlock-rs are under MIT.
The kyber BN254 port follows the original [drand/kyber](https://github.com/drand/kyber) license (Apache-2.0).

# Third-Party Notices

`tlock_age` is a composite ("Frankenstein") crate. It internalizes and modifies
source code from several upstream open-source projects in order to produce a
decrypt-only, RNG-free, `no_std`/WASM-compatible timelock library suitable for
deterministic smart-contract execution.

The crate as a whole is distributed under the Apache License, Version 2.0 (see
`LICENSE`). Portions derived from the projects below remain subject to their
original licenses; all are permissive and compatible with redistribution under
Apache-2.0. Original copyright notices are retained here as required by those
licenses.

---

## age / age_core

- **Source:** https://github.com/str4d/rage (the `age` and `age-core` crates)
- **Upstream license:** MIT OR Apache-2.0
- **Copyright:** Copyright (c) The rage Authors (Jack Grigg and contributors)
- **Files derived:** `src/age/**`, `src/age_core/**`, `src/armor.rs`
- **Modifications:** Encryption and all RNG-dependent code paths removed. Only
  the `Decryptor`, the `Identity` trait, header parsing, and ChaCha20-Poly1305
  stream decryption are retained. Serialization/write paths requiring randomness
  were stripped.

## tlock-rs

- **Source:** https://github.com/thibmeu/tlock-rs (also referenced:
  https://github.com/nicoritschel/tlock-rs)
- **Upstream license:** MIT
- **Copyright:** Copyright (c) The tlock-rs Authors
- **Files derived:** `src/tlock/**`
- **Modifications:** Decryption only. Identity-Based Encryption (IBE) decrypt
  with BLS12-381 signatures via arkworks is retained; all encryption functions
  were removed.

## kyber (BN254 pairing)

- **Source:** https://github.com/drand/kyber (Go), itself derived from
  https://github.com/dedis/kyber
- **Upstream license:** Apache-2.0 *(verify against the upstream `LICENSE`
  before publishing — see note below)*
- **Copyright:** Copyright (c) DEDIS Lab, EPFL, and the drand authors
- **Files derived:** `src/kyber/**`
- **Modifications:** A manual, byte-for-byte Rust port of the Go BN254 pairing
  and IBE implementation, restricted to the decryption path. Field arithmetic
  (`gfp`, `gfp2`, `gfp6`, `gfp12`), the Optimal Ate pairing, G1/G2 point
  operations and marshaling, and IBE decryption were translated to preserve
  exact arithmetic behavior.

---

## Verification note

Before making this repository public, confirm the exact SPDX license declared in
the upstream `drand/kyber` repository's `LICENSE` file and ensure it matches the
declaration above. If `drand/kyber` is licensed under MPL-2.0 rather than
Apache-2.0, the `src/kyber/**` files remain under MPL-2.0 (file-level copyleft)
and the crate's overall license expression should be stated as
`Apache-2.0 AND MPL-2.0`, with those files marked accordingly. Publishing the
source satisfies MPL-2.0's source-availability requirement in either case.

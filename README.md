# santoku-monocypher

A Lua binding around the [Monocypher](https://monocypher.org/) cryptography library,
plus a bundled SHA-256 and the EFF diceware wordlist. Built on base
[`santoku`](../lua-santoku/README.md). The module exposes an identity/key model
oriented at passphrase-derived signing and at-rest encryption, not the full
Monocypher API.

This README is a usage guide, not an API reference. **The tests are the spec**:
`test/spec/santoku/monocypher.lua` exercises the full surface; read it for the
exhaustive list. For the semantics of the underlying primitives (Argon2, EdDSA,
XChaCha20-Poly1305 AEAD), see the [Monocypher manual](https://monocypher.org/manual/).

The C source lives in `lib/santoku/monocypher.tk.c` and `lib/santoku/monocypher.tk.h`.
The `.tk` suffix marks toku build-time templates; the harness inlines the upstream
Monocypher and SHA-256 sources and the wordlist, then compiles the generated C.
The Lua module name is `santoku.monocypher` (from `luaopen_santoku_monocypher`).

## Object model

Two userdata types, both wiped on garbage collection:

- **identity**: derived from a passphrase via Argon2id. Holds a subject id, an
  Argon2 salt, an EdDSA signing/public key pair, and the Argon2 parameters. Signs
  messages and requests; exports to a plain table and re-imports from one.
- **key**: a 32-byte symmetric key derived from an identity. Encrypts and decrypts
  with XChaCha20-Poly1305 AEAD; exports to base64 and re-imports from it.

Identity and key derivation from the same passphrase and parameters are
deterministic, so the same inputs reproduce the same subject, keys, and signatures.

## Module functions  ·  test/spec/santoku/monocypher.lua

- `generate()` returns a six-word EFF diceware passphrase; `validate(secret)`
  returns whether a string is six or more valid (whitespace-split) wordlist tokens.
- `derive_identity(secret, [memory], [passes])` returns an identity; `memory`
  (Argon2 blocks, default 65536) and `passes` (default 3) tune the work factor.
- `derive_key(secret, identity)` returns a key.
- `import_identity(table)` / `import_key(base64)` rebuild a userdata from exported
  form.
- `wrap_key(key, wrap_bytes)` / `unwrap_key(base64, wrap_bytes)` AEAD-encrypt a key
  under an external 32-byte wrapping key; `wrap_bytes` must be exactly 32 bytes.
- `verify_request(public_key_b64, signature_b64, sub_b64, body)` checks an EdDSA
  signature over `sub:body`; returns `true`, or `nil, "invalid_signature"`.
- `hmac_sha256(key, message)` returns a 64-char hex HMAC-SHA-256 string.

covers: `generate`, `validate`, `derive_identity`, `derive_key`,
`import_identity`, `import_key`, `wrap_key`, `unwrap_key`, `verify_request`,
`hmac_sha256` cases in `test/spec/santoku/monocypher.lua`.

## Identity methods  ·  test/spec/santoku/monocypher.lua

`sub()` and `public_key()` return base64 strings. `sign(message)` and
`sign_request(body)` return base64 EdDSA signatures (`sign_request` signs
`sub:body`). `export()` returns a table with `sub`, `salt`, `signing_key`,
`public_key`, `argon2_memory`, `argon2_passes`.

covers: `identity sign and export`, `import_identity roundtrip`,
`sign_request and verify_request`, the argon2-param cases.

## Key methods  ·  test/spec/santoku/monocypher.lua

`encrypt(plaintext)` returns base64 ciphertext (version byte, 24-byte nonce, AEAD
ciphertext and tag); `decrypt(base64)` returns the plaintext, or
`nil, "decryption failed"` on a bad key or tampered input. `export()` returns the
32-byte key as base64. `hmac(message)` returns a 64-char hex HMAC-SHA-256 under the
key. `hash_ivec(ivec)` HMACs each int64 of a matrix `tk_ivec_t` in place (requires
santoku-matrix; see the test for its surface).

covers: `encrypt decrypt roundtrip`, `encrypt decrypt empty string`,
`decrypt wrong key fails`, `import_key roundtrip`, `key hmac`.

## Canonical flow

```lua
local crypto = require("santoku.monocypher")

local secret = crypto.generate()              -- six EFF diceware words
assert(crypto.validate(secret))

local id = crypto.derive_identity(secret)     -- Argon2id; deterministic per secret
local key = crypto.derive_key(secret, id)

local ct = key:encrypt("hello world")         -- XChaCha20-Poly1305, base64
assert(key:decrypt(ct) == "hello world")

local sig = id:sign_request("request body")   -- EdDSA over sub:body
assert(crypto.verify_request(id:public_key(), sig, id:sub(), "request body"))
```

## Building / testing

This repo uses the `toku` build harness. Tests live in `test/spec/santoku/`. The
`.tk.c` / `.tk.h` templates inline the vendored Monocypher and SHA-256 sources from
`res/` and the EFF wordlist; run the suite through `toku` so the native module is
compiled and on the path.

## License

This MIT license covers the Lua binding only. Monocypher itself is distributed
under its own license (see the upstream project); the bundled SHA-256 and EFF
wordlist carry their own terms.

MIT License

Copyright 2025 Birch Point SWE

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

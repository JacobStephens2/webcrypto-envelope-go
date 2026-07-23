# webcrypto-envelope-go

[![Go Reference](https://pkg.go.dev/badge/github.com/JacobStephens2/webcrypto-envelope-go.svg)](https://pkg.go.dev/github.com/JacobStephens2/webcrypto-envelope-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/JacobStephens2/webcrypto-envelope-go)](https://goreportcard.com/report/github.com/JacobStephens2/webcrypto-envelope-go)
[![CI](https://github.com/JacobStephens2/webcrypto-envelope-go/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobStephens2/webcrypto-envelope-go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Tiny, dependency-free AES-256-GCM envelope library for Go - the Go twin of
[@stephenspage/webcrypto-envelope](https://www.npmjs.com/package/@stephenspage/webcrypto-envelope)
([source](https://github.com/JacobStephens2/webcrypto-envelope), TypeScript, Web Crypto). The two are **wire-compatible**: an envelope
produced by either implementation opens in the other, and both test suites
prove it with fixtures sealed by the opposite side.

Two patterns, one primitive (AES-256-GCM in a compact `iv:tag:ciphertext`
base64 envelope):

1. **Password vault** - derive a key from a password (PBKDF2-SHA-256, 600k
   iterations default) and encrypt/decrypt locally. Good for offline-first
   apps that sync ciphertext the server can't read.
2. **Sealed share** - `Seal` encrypts under a fresh random key and hands the
   key back to you. Store the ciphertext anywhere (the server only ever
   holds ciphertext); deliver the key out-of-band - e.g. in a URL fragment,
   which browsers never send to the server - and the recipient `Open`s it.
   This is the zero-knowledge shareable-link primitive.

Standard library only - `crypto/pbkdf2` landed in Go 1.24, so that is the
minimum version. Every function returns an error rather than panicking on
attacker-controlled input.

## Install

```bash
go get github.com/JacobStephens2/webcrypto-envelope-go
```

```go
import envelope "github.com/JacobStephens2/webcrypto-envelope-go"
```

## Password vault

```go
salt := envelope.RandomSalt() // store alongside the ciphertext

key, err := envelope.DeriveKey(password, salt, nil) // nil = 600k iterations
if err != nil {
	return err
}
env, err := envelope.Encrypt(`{"observations":[...]}`, key)
// env is "iv:tag:ciphertext" base64 - safe to store anywhere

plain, err := envelope.Decrypt(env, key) // errors on wrong key or tampering
```

## Sealed share (zero-knowledge link)

```go
key, env, err := envelope.Seal(payload)
if err != nil {
	return err
}
// Store env server-side; put key in the URL fragment:
shareURL := "https://app.example.com/share/" + id + "#" + url.PathEscape(key)

// Recipient side:
plain, err := envelope.Open(env, key)
```

The fragment never reaches the server, so the storage service is
zero-knowledge with respect to the content.

## Cross-language interop

The envelope format is identical across both implementations: 12-byte GCM
IV, 16-byte tag, ciphertext - each standard-base64, joined with `:`.
PBKDF2-SHA-256 keys derive identically from the same password, salt, and
iteration count.

- This repo's tests open envelopes sealed by the TypeScript library
  (`TestOpensTypeScriptSealedEnvelopes`).
- The TypeScript repo's tests open envelopes sealed by this library.

Encrypt in a browser, decrypt in a Go service - or the reverse.

## API

| Function | Purpose |
|---|---|
| `DeriveKey(password, saltB64, opts)` | PBKDF2-SHA-256 → 32-byte AES key (`opts` may be nil) |
| `Encrypt(plaintext, key)` | Encrypt to an `iv:tag:ciphertext` envelope, fresh IV per call |
| `Decrypt(envelope, key)` | Open an envelope; errors on wrong key or tampering |
| `Seal(plaintext)` | Encrypt under a fresh random key; returns `(key, envelope, err)` |
| `Open(envelope, keyB64)` | Open a sealed payload with its base64 key |
| `RandomSalt()` | Random base64 16-byte salt |
| `RandomKey()` | Random base64 256-bit key |

## Security notes

- **GCM authenticates.** `Decrypt`/`Open` fail on any tampering - there is no
  unauthenticated mode.
- **A fresh random IV per `Encrypt` call.** Never reuse an envelope's IV with
  the same key for new plaintext.
- **PBKDF2 is for passwords only.** `Seal`/`Open` use a full-entropy random
  key and skip derivation entirely.
- **The envelope is confidential, not anonymous.** Lengths leak: ciphertext
  length equals plaintext length.

## License

MIT © Jacob Stephens

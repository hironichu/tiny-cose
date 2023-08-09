# Tiny COSE

[![](https://img.shields.io/github/actions/workflow/status/levischuck/tiny-cose/build.yml?branch=main)](https://github.com/LeviSchuck/tiny-cose/actions)
[![](https://img.shields.io/codecov/c/gh/levischuck/tiny-cose?style=flat-square)](https://codecov.io/gh/levischuck/tiny-cose)
[![](https://img.shields.io/github/v/tag/levischuck/tiny-cose?label=npm&logo=npm&style=flat-square)](https://www.npmjs.com/package/@levischuck/tiny-cose)
[![](https://img.shields.io/github/v/tag/levischuck/tiny-cose?label=version&logo=deno&style=flat-square)](https://deno.land/x/tiny_cose)
[![](https://img.shields.io/github/license/levischuck/tiny-cose)](https://github.com/LeviSchuck/tiny-cose/blob/main/LICENSE.txt)
![](https://img.shields.io/bundlephobia/min/%40levischuck/tiny-cose)

A very incomplete COSE library for use with other `tiny-*` libraries.

## What's inside

This implementation provides:

- Deserializing public and private key objects into JavaScript `CryptoKey`s
- Serializing JavaScript private and public `CryptoKey`s into public and private
  COSE key objects
- Deserializing and serializing symmetric `CryptoKey`s into COSE key objects

This implementation omits:

- Signing data with private keys
- Verifying data with public keys
- MACing data with symmetric keys
- Verifying MACd data with symmetric keys
- Direct Encryption of data with symmetric keys
- Direct Decryption of data with symmetric keys
- Encrypting data with asymmetric keys with ephemeral-static / static-static key
  agreement
- Decrypting data with asymmetric keys with ephemeral-static / static-static key
  agreement
- Key agreement with key wrapping
- Key transport
- ECDH
- Key Derivation Functions

This implementation does not support:

- RSA keys with multiple primes
- Elliptic Curve keys with compressed points
- `CryptoKey`s for symmetric encryption with AES
- RSAES-OAEP
- Private keys without public components
- ES512 / Curve P-521, see Deno Issue
  [P-521 curves in WebCrypto](https://github.com/denoland/deno/issues/13449)

Over time, this list may change.

## Warning

COSE cryptography is, in general, unsafe for most to dabble with. Please consult
a cryptographer when you are inventing something new with cryptographic
constructs.

## Standards References

- [RFC9052 - CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC9053 - CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC9054 - CBOR Object Signing and Encryption (COSE): Hash Algorithms](https://www.rfc-editor.org/rfc/rfc9054.html)
- [RFC8230 - Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages](https://www.rfc-editor.org/rfc/rfc8230.html)
- [RFC8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms](https://www.rfc-editor.org/rfc/rfc8812.html)

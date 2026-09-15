# ChaCha20 NEON test

This original wg-nx test code is `LGPL-3.0-or-later` (see the repository
license files). Vendored Monocypher remains BSD-2-Clause OR CC0-1.0.

On an ARM64 host with Clang, from the `switch-wireguard` directory:

```sh
clang -O3 -std=c11 -I src -I library/crypto \
  tests/chacha20_neon_test.c src/wg_chacha20_neon.c \
  src/wg_poly1305_neon.c library/crypto/monocypher.c \
  -o /tmp/wg-chacha-neon-test
/tmp/wg-chacha-neon-test
```

Add `-DWG_CHACHA20_4BLOCK=0` to compare the previous one-block path.
The test checks ChaCha20 output against Monocypher, AEAD tags and tampering,
varied lengths and alignment, and in-place encrypt/decrypt. Its throughput
figures are host microbenchmarks, not Switch CPU measurements.

/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2026 xlanor
 * This file is part of wg-nx. See COPYING and COPYING.LESSER.
 */

#include "wg_chacha20_neon.h"
#include "monocypher.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef WG_BENCH_ITERATIONS
#define WG_BENCH_ITERATIONS 1000000
#endif

static uint8_t input[2048];
static uint8_t expected[2048];
static uint8_t actual[2048];
static volatile uint8_t benchmark_sink;

static double seconds_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

int main(void) {
    uint8_t key[32], nonce[12];
    const size_t lengths[] = {
        0, 1, 15, 16, 63, 64, 65, 127, 128, 255, 256, 257,
        288, 576, 1024, 1420, 2048
    };
    const uint32_t counters[] = {1, 7, UINT32_MAX - 64};

    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(i * 13 + 5);
    for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(i * 17 + 9);
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)(i * 29 + 3);

    if (!wg_chacha20_neon_available()) {
        fprintf(stderr, "NEON unavailable; run this test on an ARM64 host\n");
        return 1;
    }

    for (size_t c = 0; c < sizeof(counters) / sizeof(counters[0]); ++c) {
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
            size_t len = lengths[i];
            crypto_chacha20_ietf(expected, input, len, key, nonce, counters[c]);
            wg_chacha20_neon(actual, input, len, key, nonce, counters[c]);
            if (memcmp(expected, actual, len) != 0) {
                fprintf(stderr, "out-of-place mismatch: len=%zu counter=%u\n", len, counters[c]);
                return 1;
            }
            memcpy(actual, input, len);
            wg_chacha20_neon(actual, actual, len, key, nonce, counters[c]);
            if (memcmp(expected, actual, len) != 0) {
                fprintf(stderr, "in-place mismatch: len=%zu counter=%u\n", len, counters[c]);
                return 1;
            }
        }
    }

    /* Vary the packet length and input/output alignment; the relay receives
     * arbitrary IP packet lengths and may decrypt in place. */
    uint32_t random_state = 0x9e3779b9u;
    uint8_t unaligned_input[sizeof(input) + 4];
    uint8_t unaligned_output[sizeof(input) + 4];
    for (int trial = 0; trial < 1000; ++trial) {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 17;
        random_state ^= random_state << 5;
        size_t len = random_state % (sizeof(input) + 1);
        uint32_t counter = random_state & 0xffffu;
        for (size_t i = 0; i < sizeof(unaligned_input); ++i) {
            unaligned_input[i] = (uint8_t)(i + trial * 23);
        }
        crypto_chacha20_ietf(expected, unaligned_input + 3, len, key, nonce, counter);
        memset(unaligned_output, 0xa5, sizeof(unaligned_output));
        wg_chacha20_neon(unaligned_output + 1, unaligned_input + 3, len, key, nonce, counter);
        if (memcmp(expected, unaligned_output + 1, len) != 0 ||
            unaligned_output[len + 1] != 0xa5) {
            fprintf(stderr, "unaligned mismatch: len=%zu counter=%u\n", len, counter);
            return 1;
        }
        memcpy(unaligned_output + 1, unaligned_input + 3, len);
        wg_chacha20_neon(unaligned_output + 1, unaligned_output + 1, len, key, nonce, counter);
        if (memcmp(expected, unaligned_output + 1, len) != 0) {
            fprintf(stderr, "unaligned in-place mismatch: len=%zu counter=%u\n", len, counter);
            return 1;
        }
    }

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t len = lengths[i];
        uint8_t ad[19];
        uint8_t sealed[sizeof(input) + 16];
        uint8_t reference[sizeof(input) + 16];
        uint8_t opened[sizeof(input)];
        uint8_t wg_nonce[12] = {0};
        const uint64_t packet_counter = 0x123456789ULL;
        for (size_t j = 0; j < sizeof(ad); ++j) ad[j] = (uint8_t)(j * 11 + 1);
        for (int byte = 0; byte < 8; ++byte) {
            wg_nonce[4 + byte] = (uint8_t)(packet_counter >> (byte * 8));
        }
        for (size_t ad_len = 0; ad_len <= sizeof(ad); ad_len += sizeof(ad)) {
            crypto_aead_ctx reference_ctx;
            crypto_aead_init_ietf(&reference_ctx, key, wg_nonce);
            crypto_aead_write(&reference_ctx, reference, reference + len, ad, ad_len, input, len);
            if (wg_aead_neon_encrypt(sealed, key, packet_counter, input, len, ad, ad_len) != 0 ||
                memcmp(sealed, reference, len + 16) != 0 ||
                wg_aead_neon_decrypt(opened, key, packet_counter, sealed, len + 16, ad, ad_len) != 0 ||
                memcmp(opened, input, len) != 0) {
                fprintf(stderr, "AEAD mismatch: len=%zu ad=%zu\n", len, ad_len);
                return 1;
            }
            memcpy(sealed, input, len);
            if (wg_aead_neon_encrypt(sealed, key, packet_counter, sealed, len, ad, ad_len) != 0 ||
                memcmp(sealed, reference, len + 16) != 0 ||
                wg_aead_neon_decrypt(sealed, key, packet_counter, sealed, len + 16, ad, ad_len) != 0 ||
                memcmp(sealed, input, len) != 0) {
                fprintf(stderr, "AEAD in-place mismatch: len=%zu ad=%zu\n", len, ad_len);
                return 1;
            }
            memcpy(sealed, reference, len + 16);
            sealed[len] ^= 1;
            if (wg_aead_neon_decrypt(opened, key, packet_counter, sealed, len + 16, ad, ad_len) == 0) {
                fprintf(stderr, "AEAD accepted modified tag: len=%zu ad=%zu\n", len, ad_len);
                return 1;
            }
        }
    }

    puts("ChaCha20 and AEAD correctness: PASS");
    /* Typical plaintext sizes from the 320/592/1056-byte transport packets
     * in the streaming log (16-byte header + 16-byte authentication tag). */
    const size_t bench_lengths[] = {288, 560, 1024};
    for (size_t i = 0; i < sizeof(bench_lengths) / sizeof(bench_lengths[0]); ++i) {
        size_t len = bench_lengths[i];
        const int iterations = WG_BENCH_ITERATIONS;
        double start = seconds_now();
        for (int n = 0; n < iterations; ++n) {
            wg_chacha20_neon(actual, input, len, key, nonce, (uint32_t)n + 1);
            benchmark_sink ^= actual[n % len];
        }
        double elapsed = seconds_now() - start;
        printf("ChaCha20 %zu B: %.1f MiB/s (%.3f s)\n", len,
               (double)iterations * (double)len / elapsed / 1048576.0, elapsed);

        uint8_t sealed[sizeof(input) + 16];
        wg_aead_neon_encrypt(sealed, key, 123, input, len, NULL, 0);
        start = seconds_now();
        for (int n = 0; n < iterations; ++n) {
            if (wg_aead_neon_decrypt(actual, key, 123, sealed, len + 16, NULL, 0) != 0) {
                fprintf(stderr, "benchmark decrypt failed\n");
                return 1;
            }
            benchmark_sink ^= actual[n % len];
        }
        elapsed = seconds_now() - start;
        printf("AEAD decrypt %zu B: %.1f MiB/s (%.3f s)\n", len,
               (double)iterations * (double)len / elapsed / 1048576.0, elapsed);
    }
    return 0;
}

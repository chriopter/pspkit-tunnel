#ifndef TS_CRYPTO_H
#define TS_CRYPTO_H

/* Every primitive Tailscale's four protocols stand on. Control and WireGuard
   are both Noise over X25519, ChaCha20-Poly1305 and BLAKE2s; DERP's greeting
   and disco are NaCl boxes, which are X25519 and XSalsa20-Poly1305. wolfSSL
   already carries X25519, ChaCha20-Poly1305 and Poly1305 for TLS, so those
   are borrowed from it; BLAKE2s and Salsa20 it does not have, and live here. */

#include <stddef.h>
#include <stdint.h>

#define KEY_LEN 32
#define TAG_LEN 16
#define BOX_NONCE_LEN 24

typedef struct {
    uint32_t h[8], t[2];
    uint8_t buf[64];
    size_t c, outlen;
} blake2s_ctx;

void blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t len);
void blake2s_final(blake2s_ctx *ctx, uint8_t *out);
void blake2s(uint8_t *out, size_t outlen, const void *key, size_t keylen,
             const void *in, size_t len);

/* The Noise KDF: HKDF over HMAC-BLAKE2s with the chaining key as salt,
   giving up to three 32-byte outputs. out2 and out3 may be NULL. */
void hkdf(uint8_t out1[32], uint8_t out2[32], uint8_t out3[32],
          const uint8_t ck[32], const void *ikm, size_t ikm_len);

/* A fresh private key, clamped here once: wolfSSL's scalar multiplication
   does not clamp, Go's does, so a key has to be in clamped form before it
   is ever used for the two sides to agree. */
void x25519_keygen(uint8_t priv[32], uint8_t pub[32]);
void x25519_public(uint8_t pub[32], const uint8_t priv[32]);
/* Returns -1 if the result is all zero -- a low-order point from the peer. */
int x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);

/* ChaCha20-Poly1305 with the tag after the ciphertext, as both Noise
   variants lay it out. out holds len + 16; open returns -1 on a bad tag. */
void aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
               const void *pt, size_t len, const void *ad, size_t adlen);
int aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
              const void *ct, size_t len, const void *ad, size_t adlen);

/* NaCl crypto_box, in Go's layout: 16-byte tag, then the ciphertext. */
void box_seal(uint8_t *out, const void *msg, size_t len, const uint8_t nonce[24],
              const uint8_t their_pub[32], const uint8_t my_priv[32]);
int box_open(uint8_t *out, const void *boxed, size_t len, const uint8_t nonce[24],
             const uint8_t their_pub[32], const uint8_t my_priv[32]);

/* Randomness comes from the platform: plat_random. */
void random_bytes(void *out, size_t len);

void hex_encode(char *out, const uint8_t *in, size_t len);
int hex_decode(uint8_t *out, size_t len, const char *in);
size_t base64_encode(char *out, const uint8_t *in, size_t len);

#endif

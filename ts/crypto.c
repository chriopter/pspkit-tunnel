#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/poly1305.h>

#include "ts/crypto.h"
#include "ts/plat.h"


static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ---------------------------------------------------------------- blake2s */

static const uint32_t B2S_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

#define G(a, b, c, d, x, y) do { \
    v[a] += v[b] + (x); v[d] = ROTR(v[d] ^ v[a], 16); \
    v[c] += v[d];       v[b] = ROTR(v[b] ^ v[c], 12); \
    v[a] += v[b] + (y); v[d] = ROTR(v[d] ^ v[a], 8);  \
    v[c] += v[d];       v[b] = ROTR(v[b] ^ v[c], 7);  \
} while (0)

static void b2s_compress(blake2s_ctx *ctx, int last) {
    uint32_t v[16], m[16];
    for (int i = 0; i < 8; i++) { v[i] = ctx->h[i]; v[i + 8] = B2S_IV[i]; }
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (last) v[14] = ~v[14];
    for (int i = 0; i < 16; i++) m[i] = load32(ctx->buf + 4 * i);
    for (int r = 0; r < 10; r++) {
        const uint8_t *s = SIGMA[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) ctx->h[i] ^= v[i] ^ v[i + 8];
}

void blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen) {
    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; i++) ctx->h[i] = B2S_IV[i];
    ctx->h[0] ^= 0x01010000 ^ (uint32_t)(keylen << 8) ^ (uint32_t)outlen;
    ctx->outlen = outlen;
    if (keylen) {
        memcpy(ctx->buf, key, keylen);
        ctx->c = 64;               /* a key is one full block of its own */
    }
}

void blake2s_update(blake2s_ctx *ctx, const void *in, size_t len) {
    const uint8_t *p = in;
    for (size_t i = 0; i < len; i++) {
        if (ctx->c == 64) {
            ctx->t[0] += 64;
            if (ctx->t[0] < 64) ctx->t[1]++;
            b2s_compress(ctx, 0);
            ctx->c = 0;
        }
        ctx->buf[ctx->c++] = p[i];
    }
}

void blake2s_final(blake2s_ctx *ctx, uint8_t *out) {
    ctx->t[0] += (uint32_t)ctx->c;
    if (ctx->t[0] < ctx->c) ctx->t[1]++;
    memset(ctx->buf + ctx->c, 0, 64 - ctx->c);
    b2s_compress(ctx, 1);
    uint8_t full[32];
    for (int i = 0; i < 8; i++) store32(full + 4 * i, ctx->h[i]);
    memcpy(out, full, ctx->outlen);
}

void blake2s(uint8_t *out, size_t outlen, const void *key, size_t keylen,
             const void *in, size_t len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, outlen, key, keylen);
    blake2s_update(&ctx, in, len);
    blake2s_final(&ctx, out);
}

/* HMAC in the RFC 2104 construction, not BLAKE2s's own keyed mode: Noise
   defines HKDF over HMAC-HASH, and WireGuard and Tailscale both follow it. */
static void hmac(uint8_t out[32], const uint8_t key[32], const void *in, size_t len) {
    uint8_t pad[64], inner[32];
    blake2s_ctx ctx;
    memset(pad, 0, sizeof(pad));
    memcpy(pad, key, 32);
    for (int i = 0; i < 64; i++) pad[i] ^= 0x36;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, 64);
    blake2s_update(&ctx, in, len);
    blake2s_final(&ctx, inner);
    for (int i = 0; i < 64; i++) pad[i] ^= 0x36 ^ 0x5c;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, 64);
    blake2s_update(&ctx, inner, 32);
    blake2s_final(&ctx, out);
}

void hkdf(uint8_t out1[32], uint8_t out2[32], uint8_t out3[32],
          const uint8_t ck[32], const void *ikm, size_t ikm_len) {
    uint8_t prk[32], t[33];
    hmac(prk, ck, ikm, ikm_len);
    t[0] = 1;
    hmac(t, prk, t, 1);
    memcpy(out1, t, 32);
    if (!out2) return;
    t[32] = 2;
    hmac(t, prk, t, 33);
    memcpy(out2, t, 32);
    if (!out3) return;
    t[32] = 3;
    hmac(t, prk, t, 33);
    memcpy(out3, t, 32);
}

/* ------------------------------------------------------------------ x25519 */

static const uint8_t BASEPOINT[32] = { 9 };

/* wolfSSL's ladder on raw little-endian bytes. It wants the scalar clamped,
   which X25519 does to it anyway, so a copy is clamped here. */
static int ladder(uint8_t out[32], const uint8_t priv[32], const uint8_t point[32]) {
    uint8_t k[32];
    memcpy(k, priv, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    int r = wc_curve25519_generic(32, out, 32, k, 32, point);
    memset(k, 0, sizeof(k));
    return r;
}

void x25519_public(uint8_t pub[32], const uint8_t priv[32]) {
    if (ladder(pub, priv, BASEPOINT) != 0) memset(pub, 0, 32);
}

void x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
    random_bytes(priv, 32);
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    x25519_public(pub, priv);
}

int x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]) {
    uint8_t p[32], acc = 0;
    memcpy(p, pub, 32);
    p[31] &= 127;                         /* RFC 7748: the top bit is ignored */
    if (ladder(out, priv, p) != 0) { memset(out, 0, 32); return -1; }
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1;
}

/* -------------------------------------------------------------------- aead */

/* RFC 8439 put together from wolfSSL's ChaCha20 and Poly1305 rather than
   taken whole: wc_ChaCha20Poly1305_Encrypt writes no tag at all for an empty
   plaintext, and every Noise handshake seals exactly that. */
static void aead_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ct, size_t len, const void *ad, size_t adlen) {
    ChaCha c;
    Poly1305 p;
    uint8_t block[64] = { 0 }, none = 0;
    wc_Chacha_SetKey(&c, key, 32);
    wc_Chacha_SetIV(&c, nonce, 0);
    wc_Chacha_Process(&c, block, block, 64);    /* block 0 keys the MAC */
    wc_Poly1305SetKey(&p, block, 32);
    wc_Poly1305_MAC(&p, ad, (word32)adlen, len ? ct : &none, (word32)len, tag, 16);
}

static void chacha_xor(uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t key[32], const uint8_t nonce[12]) {
    ChaCha c;
    wc_Chacha_SetKey(&c, key, 32);
    wc_Chacha_SetIV(&c, nonce, 1);              /* the message starts at block 1 */
    wc_Chacha_Process(&c, out, in, (word32)len);
}

void aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
               const void *pt, size_t len, const void *ad, size_t adlen) {
    if (len) chacha_xor(out, pt, len, key, nonce);
    aead_tag(out + len, key, nonce, out, len, ad, adlen);
}

int aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
              const void *ct, size_t len, const void *ad, size_t adlen) {
    const uint8_t *c = ct;
    uint8_t tag[16], diff = 0;
    if (len < TAG_LEN) return -1;
    size_t n = len - TAG_LEN;
    aead_tag(tag, key, nonce, c, n, ad, adlen);
    for (int i = 0; i < 16; i++) diff |= tag[i] ^ c[n + i];
    if (diff) return -1;
    if (n) chacha_xor(out, c, n, key, nonce);
    return 0;
}

/* ------------------------------------------------------------------ salsa20 */

#define QR(a, b, c, d) do { \
    x[b] ^= ROTL(x[a] + x[d], 7);  x[c] ^= ROTL(x[b] + x[a], 9); \
    x[d] ^= ROTL(x[c] + x[b], 13); x[a] ^= ROTL(x[d] + x[c], 18); \
} while (0)

static void salsa_rounds(uint32_t x[16]) {
    for (int i = 0; i < 10; i++) {
        QR(0, 4, 8, 12); QR(5, 9, 13, 1); QR(10, 14, 2, 6); QR(15, 3, 7, 11);
        QR(0, 1, 2, 3);  QR(5, 6, 7, 4);  QR(10, 11, 8, 9); QR(15, 12, 13, 14);
    }
}

/* The 4x4 state: constants on the diagonal, key around them, and in the
   middle either nonce and counter (Salsa20) or sixteen bytes of input
   (HSalsa20). */
static void salsa_setup(uint32_t s[16], const uint8_t key[32], const uint8_t in[16]) {
    static const uint8_t sigma[] = "expand 32-byte k";
    s[0] = load32(sigma);      s[5] = load32(sigma + 4);
    s[10] = load32(sigma + 8); s[15] = load32(sigma + 12);
    for (int i = 0; i < 4; i++) {
        s[1 + i] = load32(key + 4 * i);
        s[11 + i] = load32(key + 16 + 4 * i);
        s[6 + i] = load32(in + 4 * i);
    }
}

static void hsalsa20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16]) {
    uint32_t x[16];
    salsa_setup(x, key, in);
    salsa_rounds(x);
    static const int pick[8] = { 0, 5, 10, 15, 6, 7, 8, 9 };
    for (int i = 0; i < 8; i++) store32(out + 4 * i, x[pick[i]]);
}

/* XSalsa20 over buf, from keystream offset 0; the first 32 bytes of the
   keystream are what secretbox keys Poly1305 with, so callers pass them in
   front of the message. */
static void xsalsa20_xor(uint8_t *buf, size_t len, const uint8_t key[32],
                         const uint8_t nonce[24]) {
    uint8_t sub[32], in[16];
    hsalsa20(sub, key, nonce);
    memcpy(in, nonce + 16, 8);
    memset(in + 8, 0, 8);
    uint32_t s[16], x[16];
    salsa_setup(s, sub, in);
    uint64_t counter = 0;
    for (size_t off = 0; off < len; off += 64, counter++) {
        s[8] = (uint32_t)counter;
        s[9] = (uint32_t)(counter >> 32);
        memcpy(x, s, sizeof(x));
        salsa_rounds(x);
        uint8_t block[64];
        for (int i = 0; i < 16; i++) store32(block + 4 * i, x[i] + s[i]);
        size_t n = len - off < 64 ? len - off : 64;
        for (size_t i = 0; i < n; i++) buf[off + i] ^= block[i];
    }
}

static void box_key(uint8_t k[32], const uint8_t their_pub[32], const uint8_t my_priv[32]) {
    static const uint8_t zero[16];
    uint8_t shared[32];
    x25519(shared, my_priv, their_pub);
    hsalsa20(k, shared, zero);
}

/* Messages here are a few hundred bytes at most -- a disco ping, a DERP
   greeting -- so the work happens in one stack buffer. */
#define BOX_MAX 1024

static void poly1305(uint8_t tag[16], const uint8_t key[32], const uint8_t *m, size_t len) {
    Poly1305 p;
    wc_Poly1305SetKey(&p, key, 32);
    wc_Poly1305Update(&p, m, (word32)len);
    wc_Poly1305Final(&p, tag);
}

void box_seal(uint8_t *out, const void *msg, size_t len, const uint8_t nonce[24],
              const uint8_t their_pub[32], const uint8_t my_priv[32]) {
    uint8_t k[32], buf[32 + BOX_MAX];
    if (len > BOX_MAX) len = BOX_MAX;
    box_key(k, their_pub, my_priv);
    memset(buf, 0, 32);
    memcpy(buf + 32, msg, len);
    xsalsa20_xor(buf, 32 + len, k, nonce);
    poly1305(out, buf, buf + 32, len);
    memcpy(out + TAG_LEN, buf + 32, len);
}

int box_open(uint8_t *out, const void *boxed, size_t len, const uint8_t nonce[24],
             const uint8_t their_pub[32], const uint8_t my_priv[32]) {
    const uint8_t *b = boxed;
    uint8_t k[32], buf[32 + BOX_MAX], tag[16], diff = 0;
    if (len < TAG_LEN || len - TAG_LEN > BOX_MAX) return -1;
    size_t n = len - TAG_LEN;
    box_key(k, their_pub, my_priv);
    uint8_t polykey[32];
    memset(polykey, 0, 32);
    xsalsa20_xor(polykey, 32, k, nonce);
    poly1305(tag, polykey, b + TAG_LEN, n);
    for (int i = 0; i < 16; i++) diff |= tag[i] ^ b[i];
    if (diff) return -1;
    memset(buf, 0, 32);
    memcpy(buf + 32, b + TAG_LEN, n);
    xsalsa20_xor(buf, 32 + n, k, nonce);
    memcpy(out, buf + 32, n);
    return (int)n;
}

/* ------------------------------------------------------------------ misc */

void random_bytes(void *out, size_t len) { plat_random(out, len); }

void hex_encode(char *out, const uint8_t *in, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * len] = '\0';
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(uint8_t *out, size_t len, const char *in) {
    for (size_t i = 0; i < len; i++) {
        int hi = nibble(in[2 * i]), lo = hi < 0 ? -1 : nibble(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

size_t base64_encode(char *out, const uint8_t *in, size_t len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = alphabet[(v >> 18) & 63];
        out[o++] = alphabet[(v >> 12) & 63];
        out[o++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? alphabet[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

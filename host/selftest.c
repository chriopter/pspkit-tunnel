/* The primitives in ts/crypto.c against values computed by Go's
   golang.org/x/crypto (blake2s, curve25519, nacl/box) -- the code on the
   other end of every Tailscale connection. A mismatch here would otherwise
   surface as a handshake that silently fails to authenticate. */

#include <stdio.h>
#include <string.h>

#include "ts/crypto.h"

static int failures;

static void expect(const char *name, const uint8_t *got, size_t len, const char *want) {
    char hex[1024];
    hex_encode(hex, got, len);
    if (strcmp(hex, want) == 0) {
        printf("ok   %s\n", name);
    } else {
        printf("FAIL %s\n  got  %s\n  want %s\n", name, hex, want);
        failures++;
    }
}

int main(void) {
    uint8_t out[256], longbuf[200], key[32], priv[32], peer[32], pub[32], peer_pub[32], nonce[24];

    blake2s(out, 32, NULL, 0, "abc", 3);
    expect("blake2s abc", out, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

    for (int i = 0; i < 200; i++) longbuf[i] = (uint8_t)i;
    blake2s(out, 32, NULL, 0, longbuf, 200);
    expect("blake2s 200 bytes", out, 32, "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741");

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    blake2s(out, 16, key, 32, longbuf, 116);
    expect("keyed blake2s-128 (mac1)", out, 16, "57dc0e6cdcd13dfea0bf22173b0f3f1e");

    /* Noise seals empty payloads for their tag alone; that path is easy to
       get wrong and is the first thing a handshake depends on. */
    uint8_t ad[32], zero_nonce[12] = { 0 };
    for (int i = 0; i < 32; i++) { key[i] = (uint8_t)i; ad[i] = (uint8_t)(100 + i); }
    aead_seal(out, key, zero_nonce, NULL, 0, ad, 32);
    expect("chacha20-poly1305, empty", out, 16, "1d65cbfbfa6c73b4e1e02b16983dbc59");
    aead_seal(out, key, zero_nonce, key, 32, ad, 32);
    expect("chacha20-poly1305, 32 bytes", out, 48,
           "18b94032a9e3a0d61b68566aa34e4028e8a0e1e6f5b84d4bf4e1e60936286b43"
           "8383d082a4370c29e67d68f388428621");

    for (int i = 0; i < 32; i++) { priv[i] = (uint8_t)(3 * i); peer[i] = (uint8_t)(7 * i + 1); }
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
    peer[0] &= 248; peer[31] &= 127; peer[31] |= 64;
    x25519_public(pub, priv);
    expect("x25519 public", pub, 32, "d06a9f82b0d8d3cf74c8f68dee92fd99064de174d8a30cfe63aa19ce304c345a");
    x25519_public(peer_pub, peer);
    x25519(out, priv, peer_pub);
    expect("x25519 shared", out, 32, "e200e4f3fe6b079aca4974ae390d28d63e89477bc65cf6089d24e5f3bb79c725");

    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i * 5);
    const char *msg = "{\"version\":2,\"CanAckPings\":true} and some more bytes to cross a block "
                      "boundary, sixty-four is the salsa block";
    size_t mlen = strlen(msg);
    box_seal(out, msg, mlen, nonce, peer_pub, priv);
    expect("nacl box", out, mlen + 16,
           "98052bbd234ec0be90127cd1f5109c210dc9c46bb9d8825b11a95ada49ee2ede522b840c25196f3cbe256686db19c0"
           "d761cf8da08b4abdf8f7e6cbc814564e72c146affed664b25b734bd20a12bd7a0b8904ba605ebcfd6d9d47c16df97e"
           "7f71ed601524cf7a39872cd610aa6a1d1c709465685cb6fe5782d40f14079e");

    uint8_t opened[256];
    int n = box_open(opened, out, mlen + 16, nonce, pub, peer);
    if (n != (int)mlen || memcmp(opened, msg, mlen) != 0) { printf("FAIL box open\n"); failures++; }
    else printf("ok   box open, from the other side\n");
    out[20] ^= 1;
    if (box_open(opened, out, mlen + 16, nonce, pub, peer) >= 0) { printf("FAIL box forgery accepted\n"); failures++; }
    else printf("ok   box forgery refused\n");

    printf(failures ? "%d failed\n" : "all passed\n", failures);
    return failures ? 1 : 0;
}

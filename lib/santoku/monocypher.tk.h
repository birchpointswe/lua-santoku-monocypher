#ifndef TK_MONOCYPHER_H
#define TK_MONOCYPHER_H

#define TK_MT_KEY "tk_crypto_key"
#define TK_MT_IDENTITY "tk_crypto_identity"

typedef struct {
  uint8_t key[32];
} tk_key_t;

typedef struct {
  uint8_t sub[32];
  uint8_t salt[32];
  uint8_t signing_key[64];
  uint8_t public_key[32];
} tk_identity_t;

<% return readfile("res/monocypher.h") %>

<% return readfile("res/monocypher.c") %>

<% return readfile("res/sha256.h") %>

<% return readfile("res/sha256.c") %>

static inline void tk_hmac_sha256(
  const uint8_t *key, size_t key_len,
  const uint8_t *msg, size_t msg_len,
  uint8_t *out)
{
  uint8_t k[64] = {0};
  uint8_t o_key_pad[64];
  uint8_t i_key_pad[64];
  SHA256_CTX ctx;
  if (key_len > 64) {
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_final(&ctx, k);
  } else {
    memcpy(k, key, key_len);
  }
  for (size_t i = 0; i < 64; i++) {
    o_key_pad[i] = k[i] ^ 0x5c;
    i_key_pad[i] = k[i] ^ 0x36;
  }
  uint8_t inner_hash[32];
  sha256_init(&ctx);
  sha256_update(&ctx, i_key_pad, 64);
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, inner_hash);
  sha256_init(&ctx);
  sha256_update(&ctx, o_key_pad, 64);
  sha256_update(&ctx, inner_hash, 32);
  sha256_final(&ctx, out);
}

#endif

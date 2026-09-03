#ifndef TK_MONOCYPHER_H
#define TK_MONOCYPHER_H

#define TK_MT_KEY "tk_crypto_key"
#define TK_MT_IDENTITY "tk_crypto_identity"

typedef struct {
  uint8_t key[32];
  uint8_t wiped;
} tk_key_t;

typedef struct {
  uint8_t sub[32];
  uint8_t signing_key[64];
  uint8_t public_key[32];
  uint32_t argon2_memory;
  uint32_t argon2_passes;
  uint8_t master[32];
  uint8_t has_master;
  uint8_t wiped;
} tk_identity_t;

<% return readfile("res/vendor/monocypher/monocypher.h") %>

<% return readfile("res/vendor/monocypher/monocypher.c") %>

<% return readfile("res/vendor/monocypher/sha256.h") %>

<% return readfile("res/vendor/monocypher/sha256.c") %>

#ifdef TK_MONOCYPHER_P256

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
static void arc4random_buf(void *buf, size_t n) {
  EM_ASM({
    var arr = new Uint8Array($1);
    crypto.getRandomValues(arr);
    HEAPU8.set(arr, $0);
  }, buf, n);
}
#elif defined(__linux__) && !defined(__GLIBC__) && !defined(__ANDROID__)
#include <sys/random.h>
#include <errno.h>
#include <stdlib.h>
static void arc4random_buf(void *buf, size_t n) {
  unsigned char *p = (unsigned char *) buf;
  while (n) {
    ssize_t r = getrandom(p, n, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      abort();
    }
    p += r;
    n -= (size_t) r;
  }
}
#endif

<%
  local h = readfile("res/vendor/p256/p256-m.h")
  h = h:gsub("extern int p256_generate_random[^;]*;", "")
  h = h:gsub("\nint p256_", "\nstatic inline int p256_")
  return h
%>

static int p256_generate_random (uint8_t *out, unsigned n)
{
  arc4random_buf(out, n);
  return 0;
}

<%
  local src = readfile("res/vendor/p256/p256-m.c")
  src = src:gsub('#include "p256%-m.h"', "")
  src = src:gsub("defined%(__ARM_ARCH%) && __ARM_ARCH >= 6",
    "defined(__ARM_ARCH) && !defined(__aarch64__) && __ARM_ARCH >= 6")
  src = src:gsub("\nint p256_", "\nstatic inline int p256_")
  return src
%>

#endif

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
  crypto_wipe(k, sizeof(k));
  crypto_wipe(o_key_pad, sizeof(o_key_pad));
  crypto_wipe(i_key_pad, sizeof(i_key_pad));
  crypto_wipe(inner_hash, sizeof(inner_hash));
  crypto_wipe(&ctx, sizeof(ctx));
}

#endif

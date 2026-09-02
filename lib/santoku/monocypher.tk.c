#include <santoku/lua/utils.h>
#include <santoku/monocypher.h>
#include <ctype.h>

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

int p256_generate_random (uint8_t *out, unsigned n)
{
  arc4random_buf(out, n);
  return P256_SUCCESS;
}

#define MT_IDENTITY TK_MT_IDENTITY
#define MT_KEY TK_MT_KEY
#define VERSION 0x01
#define VERSION_AAD 0x02
#define TK_PHRASE_WORDS 6

static void sha256 (const char *data, size_t len, uint8_t *out) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const BYTE *)data, len);
  sha256_final(&ctx, out);
  crypto_wipe(&ctx, sizeof(ctx));
}

typedef struct {
  uint32_t h[5];
  uint64_t len;
  uint8_t buf[64];
} tk_sha1_ctx;

static void tk_sha1_block (tk_sha1_ctx *ctx, const uint8_t *p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16)
      | ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
  for (int i = 16; i < 80; i++) {
    uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
    w[i] = (x << 1) | (x >> 31);
  }
  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
    else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
    else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
    else { f = b ^ c ^ d; k = 0xCA62C1D6; }
    uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
    e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = t;
  }
  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e;
}

static void tk_sha1_init (tk_sha1_ctx *ctx) {
  ctx->h[0] = 0x67452301; ctx->h[1] = 0xEFCDAB89; ctx->h[2] = 0x98BADCFE;
  ctx->h[3] = 0x10325476; ctx->h[4] = 0xC3D2E1F0;
  ctx->len = 0;
}

static void tk_sha1_update (tk_sha1_ctx *ctx, const uint8_t *data, size_t len) {
  size_t fill = (size_t)(ctx->len % 64);
  ctx->len += len;
  if (fill) {
    size_t take = 64 - fill;
    if (take > len) take = len;
    memcpy(ctx->buf + fill, data, take);
    data += take;
    len -= take;
    if (fill + take < 64) return;
    tk_sha1_block(ctx, ctx->buf);
  }
  while (len >= 64) {
    tk_sha1_block(ctx, data);
    data += 64;
    len -= 64;
  }
  if (len) memcpy(ctx->buf, data, len);
}

static void tk_sha1_final (tk_sha1_ctx *ctx, uint8_t *out) {
  uint64_t bits = ctx->len * 8;
  size_t fill = (size_t)(ctx->len % 64);
  ctx->buf[fill++] = 0x80;
  if (fill > 56) {
    memset(ctx->buf + fill, 0, 64 - fill);
    tk_sha1_block(ctx, ctx->buf);
    fill = 0;
  }
  memset(ctx->buf + fill, 0, 56 - fill);
  for (int i = 0; i < 8; i++)
    ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
  tk_sha1_block(ctx, ctx->buf);
  for (int i = 0; i < 5; i++) {
    out[i * 4] = (uint8_t)(ctx->h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)(ctx->h[i]);
  }
}

static void sha1 (const char *data, size_t len, uint8_t *out) {
  tk_sha1_ctx ctx;
  tk_sha1_init(&ctx);
  tk_sha1_update(&ctx, (const uint8_t *)data, len);
  tk_sha1_final(&ctx, out);
  crypto_wipe(&ctx, sizeof(ctx));
}

static void hmac_sha256 (const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t *out) {
  uint8_t k_ipad[64], k_opad[64], tk[32];
  if (key_len > 64) {
    sha256((const char *)key, key_len, tk);
    key = tk;
    key_len = 32;
  }
  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);
  for (size_t i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }
  SHA256_CTX ctx;
  uint8_t inner[32];
  sha256_init(&ctx);
  sha256_update(&ctx, k_ipad, 64);
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, inner);
  sha256_init(&ctx);
  sha256_update(&ctx, k_opad, 64);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, out);
  crypto_wipe(k_ipad, sizeof(k_ipad));
  crypto_wipe(k_opad, sizeof(k_opad));
  crypto_wipe(tk, sizeof(tk));
  crypto_wipe(inner, sizeof(inner));
  crypto_wipe(&ctx, sizeof(ctx));
}

static int identity_gc (lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  crypto_wipe(id, sizeof(*id));
  id->wiped = 1;
  return 0;
}

static int key_gc (lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  crypto_wipe(k, sizeof(*k));
  k->wiped = 1;
  return 0;
}

static int l_identity_wipe (lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  crypto_wipe(id, sizeof(*id));
  id->wiped = 1;
  return 0;
}

static int l_key_wipe (lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  crypto_wipe(k, sizeof(*k));
  k->wiped = 1;
  return 0;
}

static int l_identity_wiped (lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  lua_pushboolean(L, id->wiped ? 1 : 0);
  return 1;
}

static int l_key_wiped (lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  lua_pushboolean(L, k->wiped ? 1 : 0);
  return 1;
}

static tk_identity_t *tk_check_identity (lua_State *L, int i) {
  tk_identity_t *id = luaL_checkudata(L, i, MT_IDENTITY);
  if (id->wiped) tk_lua_error(L, "identity has been wiped");
  return id;
}

static tk_key_t *tk_check_key (lua_State *L, int i) {
  tk_key_t *k = luaL_checkudata(L, i, MT_KEY);
  if (k->wiped) tk_lua_error(L, "key has been wiped");
  return k;
}

static char *tk_dup_lstring (lua_State *L, const char *s, size_t len) {
  char *copy = malloc(len + 1);
  if (!copy) {
    tk_lua_errmalloc(L);
    return NULL;
  }
  memcpy(copy, s, len);
  copy[len] = '\0';
  return copy;
}

static int l_generate (lua_State *L) {
  luaL_checktype(L, lua_upvalueindex(1), LUA_TTABLE);
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  for (int i = 0; i < TK_PHRASE_WORDS; i++) {
    char dice[6] = {0};
    for (int j = 0; j < 5; j++) {
      uint8_t r;
      do { arc4random_buf(&r, 1); } while (r >= 252);
      dice[j] = '1' + (r % 6);
    }
    if (i > 0) luaL_addchar(&b, ' ');
    lua_getfield(L, lua_upvalueindex(1), dice);
    if (lua_type(L, -1) != LUA_TSTRING)
      return tk_lua_error(L, "missing wordlist entry");
    luaL_addvalue(&b);
  }
  luaL_pushresult(&b);
  return 1;
}

static int l_validate (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  luaL_checktype(L, lua_upvalueindex(1), LUA_TTABLE);
  int word_count = 0, all_valid = 1;
  char *copy = tk_dup_lstring(L, secret, len);
  if (!copy) return 0;
  for (char *tok = strtok(copy, " \t\n\r"); tok; tok = strtok(NULL, " \t\n\r")) {
    word_count++;
    for (char *c = tok; *c; c++) *c = (char) tolower((unsigned char) *c);
    lua_getfield(L, lua_upvalueindex(1), tok);
    if (lua_isnil(L, -1)) all_valid = 0;
    lua_pop(L, 1);
  }
  crypto_wipe(copy, len + 1);
  free(copy);
  lua_pushboolean(L, word_count >= TK_PHRASE_WORDS && all_valid);
  return 1;
}

static int l_phrase_audit (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  char *copy = tk_dup_lstring(L, secret, len);
  if (!copy) return 0;
  char *words[64];
  int n = 0;
  for (char *tok = strtok(copy, " \t\n\r"); tok && n < 64; tok = strtok(NULL, " \t\n\r")) {
    for (char *c = tok; *c; c++) *c = (char) tolower((unsigned char) *c);
    words[n++] = tok;
  }
  const char *hit = NULL;
  if (n >= 2) {
    for (int i = 0; i < n && !hit; i++)
      for (int j = i + 1; j < n; j++)
        if (strcmp(words[i], words[j]) == 0) { hit = "repeated_word"; break; }
    if (!hit) {
      int same = 1;
      for (int i = 1; i < n; i++)
        if (words[i][0] != words[0][0]) { same = 0; break; }
      if (same) hit = "same_letter";
    }
    if (!hit) {
      int asc = 1, desc = 1;
      for (int i = 1; i < n; i++) {
        if (words[i][0] != words[i - 1][0] + 1) asc = 0;
        if (words[i][0] != words[i - 1][0] - 1) desc = 0;
      }
      if (asc || desc) hit = "sequential";
    }
    if (!hit) {
      int asc = 1, desc = 1;
      for (int i = 1; i < n; i++) {
        int c = strcmp(words[i - 1], words[i]);
        if (c > 0) asc = 0;
        if (c < 0) desc = 0;
      }
      if (asc || desc) hit = "alphabetical";
    }
  }
  crypto_wipe(copy, len + 1);
  free(copy);
  if (hit) {
    lua_pushstring(L, hit);
  } else {
    lua_pushnil(L);
  }
  return 1;
}

static const char TK_ARGON2_SALT[] = "littlelist-argon2-v1";

static const char *derive_master (const char *secret, size_t secret_len,
                                  uint32_t nb_blocks, uint32_t nb_passes,
                                  uint8_t *master_out) {
  if (nb_blocks < 8 || nb_passes < 1)
    return "invalid argon2 parameters";
  if (secret_len > UINT32_MAX)
    return "secret too long";
#if SIZE_MAX / 1024 < UINT32_MAX
  if (nb_blocks > SIZE_MAX / 1024)
    return "argon2 memory too large";
#endif
  void *work_area = malloc((size_t)nb_blocks * 1024);
  if (!work_area)
    return "argon2 work area allocation failed";
  crypto_argon2_config config = { CRYPTO_ARGON2_ID, nb_blocks, nb_passes, 1 };
  crypto_argon2_inputs inputs = {
    (const uint8_t *)secret, (const uint8_t *)TK_ARGON2_SALT,
    (uint32_t)secret_len, (uint32_t)(sizeof(TK_ARGON2_SALT) - 1)
  };
  crypto_argon2(master_out, 32, work_area, config, inputs, crypto_argon2_no_extras);
  crypto_wipe(work_area, (size_t)nb_blocks * 1024);
  free(work_area);
  return NULL;
}

static int l_derive_identity (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  uint32_t nb_blocks = tk_lua_optunsigned(L, 2, "memory", 65536);
  uint32_t nb_passes = tk_lua_optunsigned(L, 3, "passes", 3);
  tk_identity_t *id = tk_lua_newuserdata(L, tk_identity_t, MT_IDENTITY, NULL, identity_gc);
  id->argon2_memory = nb_blocks;
  id->argon2_passes = nb_passes;
  const char *err = derive_master(secret, len, nb_blocks, nb_passes, id->master);
  if (err) return tk_lua_error(L, err);
  id->has_master = 1;
  tk_hmac_sha256(id->master, 32, (const uint8_t *)"littlelist-id-sub-v1", 20, id->sub);
  uint8_t seed[32];
  tk_hmac_sha256(id->master, 32, (const uint8_t *)"littlelist-id-signing-v1", 24, seed);
  crypto_eddsa_key_pair(id->signing_key, id->public_key, seed);
  crypto_wipe(seed, 32);
  return 1;
}

static int l_derive_key (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  tk_identity_t *id = tk_check_identity(L, 2);
  uint8_t master[32];
  if (id->has_master) {
    memcpy(master, id->master, 32);
  } else {
    uint32_t nb_blocks = id->argon2_memory ? id->argon2_memory : 65536;
    uint32_t nb_passes = id->argon2_passes ? id->argon2_passes : 3;
    const char *err = derive_master(secret, len, nb_blocks, nb_passes, master);
    if (err) return tk_lua_error(L, err);
    memcpy(id->master, master, 32);
    id->has_master = 1;
  }
  tk_key_t *key = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  tk_hmac_sha256(master, 32, (const uint8_t *)"littlelist-id-key-v1", 20, key->key);
  crypto_wipe(master, 32);
  return 1;
}

static int l_identity_sub(lua_State *L) {
  tk_identity_t *id = tk_check_identity(L, 1);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

static int l_identity_public_key(lua_State *L) {
  tk_identity_t *id = tk_check_identity(L, 1);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)id->public_key, 32, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

static int l_identity_sign(lua_State *L) {
  tk_identity_t *id = tk_check_identity(L, 1);
  size_t len;
  const char *msg = luaL_checklstring(L, 2, &len);
  uint8_t sig[64];
  crypto_eddsa_sign(sig, id->signing_key, (const uint8_t *)msg, len);
  char b64[88];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)sig, 64, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

static int l_identity_sign_request(lua_State *L) {
  tk_identity_t *id = tk_check_identity(L, 1);
  size_t len;
  const char *body = luaL_checklstring(L, 2, &len);
  char sub_b64[44];
  size_t sub_b64_len;
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, true, sub_b64, sizeof(sub_b64), &sub_b64_len);
  if (len > SIZE_MAX - sub_b64_len - 1)
    return tk_lua_error(L, "body too long");
  size_t msg_len = sub_b64_len + 1 + len;
  char *msg = malloc(msg_len);
  if (!msg) return tk_lua_errmalloc(L);
  memcpy(msg, sub_b64, sub_b64_len);
  msg[sub_b64_len] = ':';
  memcpy(msg + sub_b64_len + 1, body, len);
  uint8_t sig[64];
  crypto_eddsa_sign(sig, id->signing_key, (const uint8_t *)msg, msg_len);
  free(msg);
  char sig_b64[88];
  size_t sig_b64_len;
  tk_lua_to_base64_buf((const char *)sig, 64, false, true, sig_b64, sizeof(sig_b64), &sig_b64_len);
  lua_pushlstring(L, sig_b64, sig_b64_len);
  return 1;
}

static int l_identity_export(lua_State *L) {
  tk_identity_t *id = tk_check_identity(L, 1);
  char b64[88];
  size_t out_len;
  lua_newtable(L);
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "sub");
  tk_lua_to_base64_buf((const char *)id->signing_key, 64, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "signing_key");
  tk_lua_to_base64_buf((const char *)id->public_key, 32, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "public_key");
  lua_pushinteger(L, id->argon2_memory); lua_setfield(L, -2, "argon2_memory");
  lua_pushinteger(L, id->argon2_passes); lua_setfield(L, -2, "argon2_passes");
  return 1;
}

static bool import_field_b64 (lua_State *L, int i, const char *field, uint8_t *out, size_t exact) {
  lua_getfield(L, i, field);
  if (lua_type(L, -1) != LUA_TSTRING) {
    lua_pop(L, 1);
    return false;
  }
  size_t len, out_len;
  const char *str = lua_tolstring(L, -1, &len);
  bool ok = tk_lua_from_base64_buf(str, len, false, (char *)out, exact, &out_len)
    && out_len == exact;
  lua_pop(L, 1);
  return ok;
}

static int l_import_identity(lua_State *L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  tk_identity_t *id = tk_lua_newuserdata(L, tk_identity_t, MT_IDENTITY, NULL, identity_gc);
  if (!import_field_b64(L, 1, "sub", id->sub, sizeof(id->sub)) ||
      !import_field_b64(L, 1, "signing_key", id->signing_key, sizeof(id->signing_key)) ||
      !import_field_b64(L, 1, "public_key", id->public_key, sizeof(id->public_key)))
    return tk_lua_error(L, "invalid identity");
  lua_getfield(L, 1, "argon2_memory");
  id->argon2_memory = lua_isnil(L, -1) ? 65536 : (uint32_t)lua_tointeger(L, -1);
  lua_pop(L, 1);
  lua_getfield(L, 1, "argon2_passes");
  id->argon2_passes = lua_isnil(L, -1) ? 3 : (uint32_t)lua_tointeger(L, -1);
  lua_pop(L, 1);
  return 1;
}

static int l_key_export(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)k->key, 32, false, true, b64, sizeof(b64), &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

static int l_key_bytes(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  lua_pushlstring(L, (const char *)k->key, 32);
  return 1;
}

static int l_key_derive(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  size_t len;
  const char *label = luaL_checklstring(L, 2, &len);
  tk_key_t *out = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  tk_hmac_sha256(k->key, 32, (const uint8_t *) label, len, out->key);
  return 1;
}

static int l_import_key(lua_State *L) {
  size_t b64_len;
  const char *b64 = luaL_checklstring(L, 1, &b64_len);
  tk_key_t *k = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  size_t out_len;
  if (!tk_lua_from_base64_buf(b64, b64_len, false, (char *)k->key, sizeof(k->key), &out_len)
      || out_len != sizeof(k->key))
    return tk_lua_error(L, "invalid key");
  return 1;
}

static int l_key_encrypt(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  size_t len;
  const char *pt = luaL_checklstring(L, 2, &len);
  size_t ad_len = 0;
  const uint8_t *ad = NULL;
  if (!lua_isnoneornil(L, 3)) {
    ad = (const uint8_t *)luaL_checklstring(L, 3, &ad_len);
  }
  uint8_t nonce[24];
  arc4random_buf(nonce, 24);
  if (len > SIZE_MAX / 8 - 64)
    return tk_lua_error(L, "plaintext too long");
  size_t out_len = 1 + 24 + len + 16;
  size_t b64_max = tk_lua_to_base64_size(out_len, true);
  uint8_t *buf = malloc(out_len + b64_max);
  if (!buf) return tk_lua_errmalloc(L);
  buf[0] = ad_len ? VERSION_AAD : VERSION;
  memcpy(buf + 1, nonce, 24);
  crypto_aead_lock(buf + 25, buf + 25 + len, k->key, nonce, ad, ad_len, (const uint8_t *)pt, len);
  char *b64 = (char *)(buf + out_len);
  size_t b64_len;
  tk_lua_to_base64_buf((const char *)buf, out_len, false, true, b64, b64_max, &b64_len);
  lua_pushlstring(L, b64, b64_len);
  free(buf);
  return 1;
}

static int l_key_decrypt(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  size_t b64_len;
  const char *b64 = luaL_checklstring(L, 2, &b64_len);
  size_t ad_len = 0;
  const uint8_t *ad = NULL;
  if (!lua_isnoneornil(L, 3)) {
    ad = (const uint8_t *)luaL_checklstring(L, 3, &ad_len);
  }
  size_t dec_max = tk_lua_from_base64_size(tk_lua_base64_prefix(b64, b64_len, false));
  uint8_t *in = malloc(dec_max ? dec_max : 1);
  if (!in) return tk_lua_errmalloc(L);
  size_t dec_len;
  tk_lua_from_base64_buf(b64, b64_len, false, (char *)in, dec_max, &dec_len);

  if (dec_len < 1 + 24 + 16) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "unsupported version");
    return 2;
  }
  uint8_t version = in[0];
  if (version != VERSION && version != VERSION_AAD) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "unsupported version");
    return 2;
  }
  if (version != (ad_len ? VERSION_AAD : VERSION)) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "aad mismatch");
    return 2;
  }
  uint8_t *nonce = in + 1;
  size_t ct_len = dec_len - 1 - 24 - 16;
  uint8_t *ct = in + 25;
  uint8_t *mac = in + 25 + ct_len;
  uint8_t *pt = malloc(ct_len ? ct_len : 1);
  if (!pt) {
    free(in);
    return tk_lua_errmalloc(L);
  }
  int ret = crypto_aead_unlock(pt, mac, k->key, nonce, ad, ad_len, ct, ct_len);
  free(in);
  if (ret != 0) {
    free(pt);
    lua_pushnil(L);
    lua_pushstring(L, "decryption failed");
    return 2;
  }
  lua_pushlstring(L, (char *)pt, ct_len);
  crypto_wipe(pt, ct_len);
  free(pt);
  return 1;
}

static int l_wrap_key(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  size_t wrap_len;
  const char *wrap = luaL_checklstring(L, 2, &wrap_len);
  if (wrap_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "wrap_bytes must be exactly 32 bytes");
    return 2;
  }
  uint8_t nonce[24];
  arc4random_buf(nonce, 24);
  size_t out_len = 1 + 24 + 32 + 16;
  size_t b64_max = tk_lua_to_base64_size(out_len, true);
  uint8_t *buf = malloc(out_len + b64_max);
  if (!buf) return tk_lua_errmalloc(L);
  buf[0] = VERSION;
  memcpy(buf + 1, nonce, 24);
  crypto_aead_lock(buf + 25, buf + 25 + 32, (const uint8_t *)wrap, nonce, NULL, 0, k->key, 32);
  char *b64 = (char *)(buf + out_len);
  size_t b64_len;
  tk_lua_to_base64_buf((const char *)buf, out_len, false, true, b64, b64_max, &b64_len);
  lua_pushlstring(L, b64, b64_len);
  free(buf);
  return 1;
}

static int l_unwrap_key(lua_State *L) {
  size_t b64_len;
  const char *b64 = luaL_checklstring(L, 1, &b64_len);
  size_t wrap_len;
  const char *wrap = luaL_checklstring(L, 2, &wrap_len);
  if (wrap_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "wrap_bytes must be exactly 32 bytes");
    return 2;
  }
  size_t dec_max = tk_lua_from_base64_size(tk_lua_base64_prefix(b64, b64_len, false));
  uint8_t *in = malloc(dec_max ? dec_max : 1);
  if (!in) return tk_lua_errmalloc(L);
  size_t dec_len;
  tk_lua_from_base64_buf(b64, b64_len, false, (char *)in, dec_max, &dec_len);
  if (dec_len < 1 + 24 + 16 || in[0] != VERSION) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "unsupported version");
    return 2;
  }
  size_t ct_len = dec_len - 1 - 24 - 16;
  if (ct_len != 32) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "invalid wrapped key length");
    return 2;
  }
  uint8_t *nonce = in + 1;
  uint8_t *ct = in + 25;
  uint8_t *mac = in + 25 + 32;
  tk_key_t *key = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  int ret = crypto_aead_unlock(key->key, mac, (const uint8_t *)wrap, nonce, NULL, 0, ct, 32);
  free(in);
  if (ret != 0) {
    crypto_wipe(key->key, 32);
    lua_pop(L, 1);
    lua_pushnil(L);
    lua_pushstring(L, "decryption failed");
    return 2;
  }
  return 1;
}

static int l_key_hmac(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  size_t msg_len;
  const char *msg = luaL_checklstring(L, 2, &msg_len);
  uint8_t out[32];
  hmac_sha256(k->key, 32, (const uint8_t *)msg, msg_len, out);
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + i * 2, "%02x", out[i]);
  }
  lua_pushlstring(L, hex, 64);
  return 1;
}

static int l_hmac_sha256(lua_State *L) {
  size_t key_len, msg_len;
  const char *key = luaL_checklstring(L, 1, &key_len);
  const char *msg = luaL_checklstring(L, 2, &msg_len);
  uint8_t out[32];
  hmac_sha256((const uint8_t *)key, key_len, (const uint8_t *)msg, msg_len, out);
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + i * 2, "%02x", out[i]);
  }
  lua_pushlstring(L, hex, 64);
  return 1;
}

static void hmac_sha1 (const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t *out) {
  uint8_t k_ipad[64], k_opad[64], tk[20];
  if (key_len > 64) {
    sha1((const char *)key, key_len, tk);
    key = tk;
    key_len = 20;
  }
  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);
  for (size_t i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }
  tk_sha1_ctx ctx;
  uint8_t inner[20];
  tk_sha1_init(&ctx);
  tk_sha1_update(&ctx, k_ipad, 64);
  tk_sha1_update(&ctx, msg, msg_len);
  tk_sha1_final(&ctx, inner);
  tk_sha1_init(&ctx);
  tk_sha1_update(&ctx, k_opad, 64);
  tk_sha1_update(&ctx, inner, 20);
  tk_sha1_final(&ctx, out);
  crypto_wipe(k_ipad, sizeof(k_ipad));
  crypto_wipe(k_opad, sizeof(k_opad));
  crypto_wipe(tk, sizeof(tk));
  crypto_wipe(inner, sizeof(inner));
  crypto_wipe(&ctx, sizeof(ctx));
}

static int l_hmac_sha1(lua_State *L) {
  size_t key_len, msg_len;
  const char *key = luaL_checklstring(L, 1, &key_len);
  const char *msg = luaL_checklstring(L, 2, &msg_len);
  uint8_t out[20];
  hmac_sha1((const uint8_t *)key, key_len, (const uint8_t *)msg, msg_len, out);
  char hex[41];
  for (int i = 0; i < 20; i++) {
    sprintf(hex + i * 2, "%02x", out[i]);
  }
  lua_pushlstring(L, hex, 40);
  return 1;
}

static int l_key_hash_ivec(lua_State *L) {
  tk_key_t *k = tk_check_key(L, 1);
  struct { size_t n, m; int64_t *a; int lua_managed; } *v =
    (void *)luaL_checkudata(L, 2, "tk_ivec_t");
  for (size_t i = 0; i < v->n; i++) {
    uint8_t msg[8], hash[32];
    memcpy(msg, &v->a[i], 8);
    hmac_sha256(k->key, 32, msg, 8, hash);
    memcpy(&v->a[i], hash, 8);
  }
  lua_pushvalue(L, 2);
  return 1;
}

static int l_verify_request(lua_State *L) {
  size_t pk_b64_len, sig_b64_len, sub_b64_len, body_len;
  const char *pk_b64 = luaL_checklstring(L, 1, &pk_b64_len);
  const char *sig_b64 = luaL_checklstring(L, 2, &sig_b64_len);
  const char *sub_b64 = luaL_checklstring(L, 3, &sub_b64_len);
  const char *body = luaL_checklstring(L, 4, &body_len);
  uint8_t sig[64], pk[32];
  size_t sig_len, pk_len;
  if (!tk_lua_from_base64_buf(sig_b64, sig_b64_len, false, (char *)sig, sizeof(sig), &sig_len) ||
      sig_len != sizeof(sig) ||
      !tk_lua_from_base64_buf(pk_b64, pk_b64_len, false, (char *)pk, sizeof(pk), &pk_len) ||
      pk_len != sizeof(pk)) {
    lua_pushnil(L);
    lua_pushstring(L, "invalid_signature");
    return 2;
  }
  if (body_len > SIZE_MAX - sub_b64_len - 1)
    return tk_lua_error(L, "body too long");
  size_t msg_len = sub_b64_len + 1 + body_len;
  char *msg = malloc(msg_len);
  if (!msg) return tk_lua_errmalloc(L);
  memcpy(msg, sub_b64, sub_b64_len);
  msg[sub_b64_len] = ':';
  memcpy(msg + sub_b64_len + 1, body, body_len);
  int valid = crypto_eddsa_check(sig, pk, (const uint8_t *)msg, msg_len) == 0;
  free(msg);
  if (!valid) {
    lua_pushnil(L);
    lua_pushstring(L, "invalid_signature");
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

static int l_const_eq(lua_State *L) {
  size_t alen, blen;
  const unsigned char *a = (const unsigned char *)luaL_checklstring(L, 1, &alen);
  const unsigned char *b = (const unsigned char *)luaL_checklstring(L, 2, &blen);
  if (alen != blen) {
    lua_pushboolean(L, 0);
    return 1;
  }
  volatile unsigned char acc = 0;
  for (size_t i = 0; i < alen; i++)
    acc |= (unsigned char)(a[i] ^ b[i]);
  lua_pushboolean(L, acc == 0);
  return 1;
}

static int l_p256_keypair (lua_State *L) {
  uint8_t priv[32], pub[64];
  if (p256_gen_keypair(priv, pub) != P256_SUCCESS)
    return luaL_error(L, "p256 keypair generation failed");
  lua_pushlstring(L, (const char *) priv, 32);
  lua_pushlstring(L, (const char *) pub, 64);
  crypto_wipe(priv, 32);
  return 2;
}

static int l_p256_sign (lua_State *L) {
  size_t plen, hlen;
  const char *priv = luaL_checklstring(L, 1, &plen);
  const char *hash = luaL_checklstring(L, 2, &hlen);
  if (plen != 32)
    return luaL_error(L, "p256 private key must be 32 bytes");
  uint8_t sig[64];
  if (p256_ecdsa_sign(sig, (const uint8_t *) priv,
      (const uint8_t *) hash, hlen) != P256_SUCCESS)
    return luaL_error(L, "p256 signing failed");
  lua_pushlstring(L, (const char *) sig, 64);
  return 1;
}

static int l_p256_verify (lua_State *L) {
  size_t publen, siglen, hlen;
  const char *pub = luaL_checklstring(L, 1, &publen);
  const char *sig = luaL_checklstring(L, 2, &siglen);
  const char *hash = luaL_checklstring(L, 3, &hlen);
  if (publen != 64 || siglen != 64) {
    lua_pushboolean(L, 0);
    return 1;
  }
  int rc = p256_ecdsa_verify((const uint8_t *) sig, (const uint8_t *) pub,
    (const uint8_t *) hash, hlen);
  lua_pushboolean(L, rc == P256_SUCCESS);
  return 1;
}

static luaL_Reg identity_methods[] = {
  {"sub", l_identity_sub},
  {"public_key", l_identity_public_key},
  {"sign", l_identity_sign},
  {"sign_request", l_identity_sign_request},
  {"export", l_identity_export},
  {"wipe", l_identity_wipe},
  {"wiped", l_identity_wiped},
  {NULL, NULL}
};

static luaL_Reg key_methods[] = {
  {"export", l_key_export},
  {"bytes", l_key_bytes},
  {"derive", l_key_derive},
  {"encrypt", l_key_encrypt},
  {"decrypt", l_key_decrypt},
  {"hmac", l_key_hmac},
  {"hash_ivec", l_key_hash_ivec},
  {"wipe", l_key_wipe},
  {"wiped", l_key_wiped},
  {NULL, NULL}
};

static luaL_Reg module_funcs[] = {
  {"derive_identity", l_derive_identity},
  {"derive_key", l_derive_key},
  {"import_identity", l_import_identity},
  {"import_key", l_import_key},
  {"wrap_key", l_wrap_key},
  {"unwrap_key", l_unwrap_key},
  {"verify_request", l_verify_request},
  {"hmac_sha256", l_hmac_sha256},
  {"hmac_sha1", l_hmac_sha1},
  {"const_eq", l_const_eq},
  {"phrase_audit", l_phrase_audit},
  {"p256_keypair", l_p256_keypair},
  {"p256_sign", l_p256_sign},
  {"p256_verify", l_p256_verify},
  {NULL, NULL}
};

<%
  local arr = require("santoku.array")
  local str = require("santoku.string")
  local data = arr.icollect(str.gmatch(readfile("res/eff.txt"), "%S+"))
  arr.map(data, str.quote)
  eff_words_len = #data
  eff_words_array = arr.concat({ "{", arr.concat(data, ","), "}" })
%>

static const size_t eff_words_len = <% return tostring(eff_words_len) %>;
static const char *eff_words[] = <% return eff_words_array %>;

int luaopen_santoku_monocypher (lua_State *L)
{

  lua_newtable(L);
  size_t word_idx = 0;
  for (int d1 = 1; d1 <= 6; d1++)
    for (int d2 = 1; d2 <= 6; d2++)
      for (int d3 = 1; d3 <= 6; d3++)
        for (int d4 = 1; d4 <= 6; d4++)
          for (int d5 = 1; d5 <= 6; d5++) {
            char dice[6] = { '0'+d1, '0'+d2, '0'+d3, '0'+d4, '0'+d5, '\0' };
            lua_pushstring(L, eff_words[word_idx++]);
            lua_setfield(L, -2, dice);
          }
  int dice_tbl = lua_gettop(L);

  lua_newtable(L);
  for (size_t i = 0; i < eff_words_len; i++) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, eff_words[i]);
  }
  int wordset_tbl = lua_gettop(L);

  if (luaL_newmetatable(L, MT_IDENTITY)) {
    lua_pushcfunction(L, identity_gc);
    lua_setfield(L, -2, "__gc");
    lua_newtable(L);
    tk_lua_register(L, identity_methods, 0);
    lua_setfield(L, -2, "__index");
  }
  lua_pop(L, 1);

  if (luaL_newmetatable(L, MT_KEY)) {
    lua_pushcfunction(L, key_gc);
    lua_setfield(L, -2, "__gc");
    lua_newtable(L);
    tk_lua_register(L, key_methods, 0);
    lua_setfield(L, -2, "__index");
  }
  lua_pop(L, 1);

  lua_newtable(L);
  tk_lua_register(L, module_funcs, 0);

  lua_pushvalue(L, dice_tbl);
  lua_pushcclosure(L, l_generate, 1);
  lua_setfield(L, -2, "generate");

  lua_pushvalue(L, wordset_tbl);
  lua_pushcclosure(L, l_validate, 1);
  lua_setfield(L, -2, "validate");

  lua_pushvalue(L, -1);
  lua_setfield(L, LUA_REGISTRYINDEX, "tk_crypto");

  lua_replace(L, dice_tbl);
  lua_pop(L, 1);
  return 1;
}

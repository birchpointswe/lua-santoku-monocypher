#include <santoku/lua/utils.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <monocypher.h>
#include <sha256.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
static void arc4random_buf(void *buf, size_t n) {
  EM_ASM({
    var arr = new Uint8Array($1);
    crypto.getRandomValues(arr);
    HEAPU8.set(arr, $0);
  }, buf, n);
}
#else
#include <bsd/stdlib.h>
#endif

#if LUA_VERSION_NUM < 502
static void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup) {
  for (; l->name; l++) {
    for (int i = 0; i < nup; i++) lua_pushvalue(L, -nup);
    lua_pushcclosure(L, l->func, nup);
    lua_setfield(L, -(nup + 2), l->name);
  }
  lua_pop(L, nup);
}
#endif

#define MT_IDENTITY "tk_crypto_identity"
#define MT_KEY "tk_crypto_key"
#define VERSION 0x01
#define PBKDF2_ITERATIONS 600000

typedef struct {
  uint8_t sub[32];
  uint8_t salt[32];
  uint8_t signing_key[64];
  uint8_t public_key[32];
} tk_identity_t;

typedef struct {
  uint8_t key[32];
} tk_key_t;

static void sha256 (const char *data, size_t len, uint8_t *out) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const BYTE *)data, len);
  sha256_final(&ctx, out);
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
}

static void pbkdf2_sha256 (const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, int iterations, uint8_t *out) {
  uint8_t asalt[salt_len + 4];
  memcpy(asalt, salt, salt_len);
  asalt[salt_len] = 0; asalt[salt_len+1] = 0;
  asalt[salt_len+2] = 0; asalt[salt_len+3] = 1;

  uint8_t u[32], t[32];
  hmac_sha256((const uint8_t *)pass, pass_len, asalt, salt_len + 4, u);
  memcpy(t, u, 32);
  for (int i = 1; i < iterations; i++) {
    hmac_sha256((const uint8_t *)pass, pass_len, u, 32, u);
    for (int j = 0; j < 32; j++) t[j] ^= u[j];
  }
  memcpy(out, t, 32);
}

static int identity_gc (lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  crypto_wipe(id, sizeof(*id));
  return 0;
}

static int key_gc (lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  crypto_wipe(k, sizeof(*k));
  return 0;
}

// crypto.generate() - needs wordlist upvalue
static int l_generate (lua_State *L) {
  luaL_checktype(L, lua_upvalueindex(1), LUA_TTABLE);
  char result[256] = {0};
  for (int i = 0; i < 6; i++) {
    char dice[6] = {0};
    for (int j = 0; j < 5; j++) {
      uint8_t r;
      do { arc4random_buf(&r, 1); } while (r >= 252);
      dice[j] = '1' + (r % 6);
    }
    lua_getfield(L, lua_upvalueindex(1), dice);
    if (i > 0) strcat(result, "-");
    strcat(result, lua_tostring(L, -1));
    lua_pop(L, 1);
  }
  lua_pushstring(L, result);
  return 1;
}

// crypto.validate(secret)
static int l_validate (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  luaL_checktype(L, lua_upvalueindex(1), LUA_TTABLE); // wordset
  int word_count = 0, all_valid = 1;
  char *copy = strdup(secret), *p = copy;
  for (char *tok = strtok(p, " -"); tok; tok = strtok(NULL, " -")) {
    word_count++;
    for (char *c = tok; *c; c++) *c = tolower(*c);
    lua_getfield(L, lua_upvalueindex(1), tok);
    if (lua_isnil(L, -1)) all_valid = 0;
    lua_pop(L, 1);
  }
  free(copy);
  if (word_count >= 6 && all_valid) {
    lua_pushboolean(L, 1);
    return 1;
  }
  if (len >= 20) {
    int lo = 0, up = 0, dig = 0, sym = 0;
    for (size_t i = 0; i < len; i++) {
      char c = secret[i];
      if (c >= 'a' && c <= 'z') lo = 1;
      else if (c >= 'A' && c <= 'Z') up = 1;
      else if (c >= '0' && c <= '9') dig = 1;
      else sym = 1;
    }
    lua_pushboolean(L, lo && up && dig && sym);
    return 1;
  }
  lua_pushboolean(L, 0);
  return 1;
}

// crypto.derive_identity(secret)
static int l_derive_identity (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  tk_identity_t *id = tk_lua_newuserdata(L, tk_identity_t, MT_IDENTITY, NULL, identity_gc);
  char *buf = malloc(len + 16);
  sprintf(buf, "%s%s", secret, "identity");
  sha256(buf, strlen(buf), id->sub);
  sprintf(buf, "%s%s", secret, "salt");
  sha256(buf, strlen(buf), id->salt);
  uint8_t seed[32];
  sprintf(buf, "%s%s", secret, "signing");
  sha256(buf, strlen(buf), seed);
  free(buf);
  crypto_eddsa_key_pair(id->signing_key, id->public_key, seed);
  crypto_wipe(seed, 32);
  return 1;
}

// crypto.derive_key(secret, identity)
static int l_derive_key (lua_State *L) {
  size_t len;
  const char *secret = luaL_checklstring(L, 1, &len);
  tk_identity_t *id = luaL_checkudata(L, 2, MT_IDENTITY);
  tk_key_t *key = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  char *buf = malloc(len + 16);
  sprintf(buf, "%s%s", secret, "encryption");
  pbkdf2_sha256(buf, strlen(buf), id->salt, 32, PBKDF2_ITERATIONS, key->key);
  free(buf);
  return 1;
}

// identity:sub()
static int l_identity_sub(lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

// identity:public_key()
static int l_identity_public_key(lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)id->public_key, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

// identity:sign(message)
static int l_identity_sign(lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  size_t len;
  const char *msg = luaL_checklstring(L, 2, &len);
  uint8_t sig[64];
  crypto_eddsa_sign(sig, id->signing_key, (const uint8_t *)msg, len);
  char b64[88];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)sig, 64, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

// identity:sign_request(body) -> signature
static int l_identity_sign_request(lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  size_t len;
  const char *body = luaL_checklstring(L, 2, &len);
  char sub_b64[44];
  size_t sub_b64_len;
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, sub_b64, &sub_b64_len);
  size_t msg_len = sub_b64_len + 1 + len + 1;
  char *msg = malloc(msg_len);
  snprintf(msg, msg_len, "%.*s:%s", (int)sub_b64_len, sub_b64, body);
  uint8_t sig[64];
  crypto_eddsa_sign(sig, id->signing_key, (const uint8_t *)msg, strlen(msg));
  free(msg);
  char sig_b64[88];
  size_t sig_b64_len;
  tk_lua_to_base64_buf((const char *)sig, 64, false, sig_b64, &sig_b64_len);
  lua_pushlstring(L, sig_b64, sig_b64_len);
  return 1;
}

// identity:export()
static int l_identity_export(lua_State *L) {
  tk_identity_t *id = luaL_checkudata(L, 1, MT_IDENTITY);
  char b64[88];
  size_t out_len;
  lua_newtable(L);
  tk_lua_to_base64_buf((const char *)id->sub, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "sub");
  tk_lua_to_base64_buf((const char *)id->salt, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "salt");
  tk_lua_to_base64_buf((const char *)id->signing_key, 64, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "signing_key");
  tk_lua_to_base64_buf((const char *)id->public_key, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len); lua_setfield(L, -2, "public_key");
  return 1;
}

// crypto.import_identity(table)
static int l_import_identity(lua_State *L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  tk_identity_t *id = tk_lua_newuserdata(L, tk_identity_t, MT_IDENTITY, NULL, identity_gc);
  size_t len, out_len;
  const char *str;
  lua_getfield(L, 1, "sub");
  str = lua_tolstring(L, -1, &len);
  tk_lua_from_base64_buf(str, len, false, (char *)id->sub, &out_len);
  lua_pop(L, 1);
  lua_getfield(L, 1, "salt");
  str = lua_tolstring(L, -1, &len);
  tk_lua_from_base64_buf(str, len, false, (char *)id->salt, &out_len);
  lua_pop(L, 1);
  lua_getfield(L, 1, "signing_key");
  str = lua_tolstring(L, -1, &len);
  tk_lua_from_base64_buf(str, len, false, (char *)id->signing_key, &out_len);
  lua_pop(L, 1);
  lua_getfield(L, 1, "public_key");
  str = lua_tolstring(L, -1, &len);
  tk_lua_from_base64_buf(str, len, false, (char *)id->public_key, &out_len);
  lua_pop(L, 1);
  return 1;
}

// key:export()
static int l_key_export(lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  char b64[44];
  size_t out_len;
  tk_lua_to_base64_buf((const char *)k->key, 32, false, b64, &out_len);
  lua_pushlstring(L, b64, out_len);
  return 1;
}

// crypto.import_key(base64)
static int l_import_key(lua_State *L) {
  size_t b64_len;
  const char *b64 = luaL_checklstring(L, 1, &b64_len);
  tk_key_t *k = tk_lua_newuserdata(L, tk_key_t, MT_KEY, NULL, key_gc);
  size_t out_len;
  tk_lua_from_base64_buf(b64, b64_len, false, (char *)k->key, &out_len);
  return 1;
}

// key:encrypt(plaintext) - uses XChaCha20-Poly1305
static int l_key_encrypt(lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  size_t len;
  const char *pt = luaL_checklstring(L, 2, &len);
  uint8_t nonce[24];
  arc4random_buf(nonce, 24);
  size_t out_len = 1 + 24 + len + 16;
  size_t b64_max = ((out_len + 2) / 3) * 4;
  uint8_t *buf = malloc(out_len + b64_max);
  buf[0] = VERSION;
  memcpy(buf + 1, nonce, 24);
  crypto_aead_lock(buf + 25, buf + 25 + len, k->key, nonce, NULL, 0, (const uint8_t *)pt, len);
  char *b64 = (char *)(buf + out_len);
  size_t b64_len;
  tk_lua_to_base64_buf((const char *)buf, out_len, false, b64, &b64_len);
  lua_pushlstring(L, b64, b64_len);
  free(buf);
  return 1;
}

// key:decrypt(base64) -> plaintext or nil, error
static int l_key_decrypt(lua_State *L) {
  tk_key_t *k = luaL_checkudata(L, 1, MT_KEY);
  size_t b64_len;
  const char *b64 = luaL_checklstring(L, 2, &b64_len);
  size_t dec_max = (b64_len * 3) / 4;
  uint8_t *in = malloc(dec_max);
  size_t dec_len;
  tk_lua_from_base64_buf(b64, b64_len, false, (char *)in, &dec_len);
  if (in[0] != VERSION) {
    free(in);
    lua_pushnil(L);
    lua_pushstring(L, "unsupported version");
    return 2;
  }
  uint8_t *nonce = in + 1;
  size_t ct_len = dec_len - 1 - 24 - 16;
  uint8_t *ct = in + 25;
  uint8_t *mac = in + 25 + ct_len;
  uint8_t *pt = malloc(ct_len);
  int ret = crypto_aead_unlock(pt, mac, k->key, nonce, NULL, 0, ct, ct_len);
  free(in);
  if (ret != 0) {
    free(pt);
    lua_pushnil(L);
    lua_pushstring(L, "decryption failed");
    return 2;
  }
  lua_pushlstring(L, (char *)pt, ct_len);
  free(pt);
  return 1;
}

// crypto.verify_request(public_key_b64, signature_b64, sub_b64, body)
static int l_verify_request(lua_State *L) {
  size_t pk_b64_len, sig_b64_len;
  const char *pk_b64 = luaL_checklstring(L, 1, &pk_b64_len);
  const char *sig_b64 = luaL_checklstring(L, 2, &sig_b64_len);
  const char *sub_b64 = luaL_checkstring(L, 3);
  size_t body_len;
  const char *body = luaL_checklstring(L, 4, &body_len);
  uint8_t sig[64];
  size_t out_len;
  tk_lua_from_base64_buf(sig_b64, sig_b64_len, false, (char *)sig, &out_len);
  uint8_t pk[32];
  tk_lua_from_base64_buf(pk_b64, pk_b64_len, false, (char *)pk, &out_len);
  size_t msg_len = strlen(sub_b64) + 1 + body_len + 1;
  char *msg = malloc(msg_len);
  snprintf(msg, msg_len, "%s:%s", sub_b64, body);
  int valid = crypto_eddsa_check(sig, pk, (const uint8_t *)msg, strlen(msg)) == 0;
  free(msg);
  if (!valid) {
    lua_pushnil(L);
    lua_pushstring(L, "invalid_signature");
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

static luaL_Reg identity_methods[] = {
  {"sub", l_identity_sub},
  {"public_key", l_identity_public_key},
  {"sign", l_identity_sign},
  {"sign_request", l_identity_sign_request},
  {"export", l_identity_export},
  {NULL, NULL}
};

static luaL_Reg key_methods[] = {
  {"export", l_key_export},
  {"encrypt", l_key_encrypt},
  {"decrypt", l_key_decrypt},
  {NULL, NULL}
};

static luaL_Reg module_funcs[] = {
  {"derive_identity", l_derive_identity},
  {"derive_key", l_derive_key},
  {"import_identity", l_import_identity},
  {"import_key", l_import_key},
  {"verify_request", l_verify_request},
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
  // dice->word table for generate
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

  // wordset table for validate
  lua_newtable(L);
  for (size_t i = 0; i < eff_words_len; i++) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, eff_words[i]);
  }
  int wordset_tbl = lua_gettop(L);

  // identity metatable
  if (luaL_newmetatable(L, MT_IDENTITY)) {
    lua_pushcfunction(L, identity_gc);
    lua_setfield(L, -2, "__gc");
    lua_newtable(L);
    luaL_setfuncs(L, identity_methods, 0);
    lua_setfield(L, -2, "__index");
  }
  lua_pop(L, 1);

  // key metatable
  if (luaL_newmetatable(L, MT_KEY)) {
    lua_pushcfunction(L, key_gc);
    lua_setfield(L, -2, "__gc");
    lua_newtable(L);
    luaL_setfuncs(L, key_methods, 0);
    lua_setfield(L, -2, "__index");
  }
  lua_pop(L, 1);

  lua_newtable(L);
  luaL_setfuncs(L, module_funcs, 0);

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

// Monocypher version 4.0.1
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0

#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <stddef.h>
#include <stdint.h>

// Constant time comparisons
static inline int crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
static inline int crypto_verify32(const uint8_t a[32], const uint8_t b[32]);
static inline int crypto_verify64(const uint8_t a[64], const uint8_t b[64]);

// Erase sensitive data
static inline void crypto_wipe(void *secret, size_t size);

// Authenticated encryption
static inline void crypto_aead_lock(uint8_t *cipher_text, uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *ad, size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
static inline int crypto_aead_unlock(uint8_t *plain_text, const uint8_t mac[16],
                       const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Authenticated stream
typedef struct {
	uint64_t counter;
	uint8_t  key[32];
	uint8_t  nonce[8];
} crypto_aead_ctx;

static inline void crypto_aead_init_x(crypto_aead_ctx *ctx,
                        const uint8_t key[32], const uint8_t nonce[24]);
static inline void crypto_aead_init_djb(crypto_aead_ctx *ctx,
                          const uint8_t key[32], const uint8_t nonce[8]);
static inline void crypto_aead_init_ietf(crypto_aead_ctx *ctx,
                           const uint8_t key[32], const uint8_t nonce[12]);
static inline void crypto_aead_write(crypto_aead_ctx *ctx, uint8_t *cipher_text,
                       uint8_t mac[16], const uint8_t *ad, size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);
static inline int crypto_aead_read(crypto_aead_ctx *ctx, uint8_t *plain_text,
                     const uint8_t mac[16], const uint8_t *ad, size_t ad_size,
                     const uint8_t *cipher_text, size_t text_size);

// General purpose hash (BLAKE2b)
static inline void crypto_blake2b(uint8_t *hash, size_t hash_size,
                    const uint8_t *message, size_t message_size);
static inline void crypto_blake2b_keyed(uint8_t *hash, size_t hash_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *message, size_t message_size);

typedef struct {
	uint64_t hash[8];
	uint64_t input_offset[2];
	uint64_t input[16];
	size_t   input_idx;
	size_t   hash_size;
} crypto_blake2b_ctx;

static inline void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size);
static inline void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const uint8_t *key, size_t key_size);
static inline void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size);
static inline void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);

// Password key derivation (Argon2)
#define CRYPTO_ARGON2_D  0
#define CRYPTO_ARGON2_I  1
#define CRYPTO_ARGON2_ID 2

typedef struct {
	uint32_t algorithm;
	uint32_t nb_blocks;
	uint32_t nb_passes;
	uint32_t nb_lanes;
} crypto_argon2_config;

typedef struct {
	const uint8_t *pass;
	const uint8_t *salt;
	uint32_t pass_size;
	uint32_t salt_size;
} crypto_argon2_inputs;

typedef struct {
	const uint8_t *key;
	const uint8_t *ad;
	uint32_t key_size;
	uint32_t ad_size;
} crypto_argon2_extras;

static const crypto_argon2_extras crypto_argon2_no_extras = {0, 0, 0, 0};

static inline void crypto_argon2(uint8_t *hash, uint32_t hash_size, void *work_area,
                   crypto_argon2_config config, crypto_argon2_inputs inputs,
                   crypto_argon2_extras extras);

// Key exchange (X-25519)
static inline void crypto_x25519_public_key(uint8_t public_key[32],
                              const uint8_t secret_key[32]);
static inline void crypto_x25519(uint8_t raw_shared_secret[32],
                   const uint8_t your_secret_key[32],
                   const uint8_t their_public_key[32]);
static inline void crypto_x25519_to_eddsa(uint8_t eddsa[32], const uint8_t x25519[32]);
static inline void crypto_x25519_inverse(uint8_t blind_salt[32],
                           const uint8_t private_key[32],
                           const uint8_t curve_point[32]);
static inline void crypto_x25519_dirty_small(uint8_t pk[32], const uint8_t sk[32]);
static inline void crypto_x25519_dirty_fast(uint8_t pk[32], const uint8_t sk[32]);

// Signatures (EdDSA)
static inline void crypto_eddsa_key_pair(uint8_t secret_key[64],
                           uint8_t public_key[32], uint8_t seed[32]);
static inline void crypto_eddsa_sign(uint8_t signature[64],
                       const uint8_t secret_key[64],
                       const uint8_t *message, size_t message_size);
static inline int crypto_eddsa_check(const uint8_t signature[64],
                       const uint8_t public_key[32],
                       const uint8_t *message, size_t message_size);
static inline void crypto_eddsa_to_x25519(uint8_t x25519[32], const uint8_t eddsa[32]);
static inline void crypto_eddsa_trim_scalar(uint8_t out[32], const uint8_t in[32]);
static inline void crypto_eddsa_reduce(uint8_t reduced[32], const uint8_t expanded[64]);
static inline void crypto_eddsa_mul_add(uint8_t r[32], const uint8_t a[32],
                          const uint8_t b[32], const uint8_t c[32]);
static inline void crypto_eddsa_scalarbase(uint8_t point[32], const uint8_t scalar[32]);
static inline int crypto_eddsa_check_equation(const uint8_t signature[64],
                                const uint8_t public_key[32],
                                const uint8_t h_ram[32]);

// Chacha20
static inline void crypto_chacha20_h(uint8_t out[32], const uint8_t key[32],
                       const uint8_t in[16]);
static inline uint64_t crypto_chacha20_djb(uint8_t *cipher_text,
                             const uint8_t *plain_text, size_t text_size,
                             const uint8_t key[32], const uint8_t nonce[8],
                             uint64_t ctr);
static inline uint32_t crypto_chacha20_ietf(uint8_t *cipher_text,
                              const uint8_t *plain_text, size_t text_size,
                              const uint8_t key[32], const uint8_t nonce[12],
                              uint32_t ctr);
static inline uint64_t crypto_chacha20_x(uint8_t *cipher_text,
                           const uint8_t *plain_text, size_t text_size,
                           const uint8_t key[32], const uint8_t nonce[24],
                           uint64_t ctr);

// Poly 1305
static inline void crypto_poly1305(uint8_t mac[16], const uint8_t *message,
                     size_t message_size, const uint8_t key[32]);

typedef struct {
	uint8_t  c[16];
	size_t   c_idx;
	uint32_t r[4];
	uint32_t pad[4];
	uint32_t h[5];
} crypto_poly1305_ctx;

static inline void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);
static inline void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);
static inline void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);

// Elligator 2
static inline void crypto_elligator_map(uint8_t curve[32], const uint8_t hidden[32]);
static inline int crypto_elligator_rev(uint8_t hidden[32], const uint8_t curve[32],
                          uint8_t tweak);
static inline void crypto_elligator_key_pair(uint8_t hidden[32], uint8_t secret_key[32],
                               uint8_t seed[32]);

#endif // MONOCYPHER_H

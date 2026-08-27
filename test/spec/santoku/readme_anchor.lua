local test = require("santoku.test")

local err = require("santoku.error")
local assert = err.assert

local validate = require("santoku.validate")
local eq = validate.isequal

local crypto = require("santoku.monocypher")

test("derive a signing identity from a passphrase, deterministically", function ()
  local a = crypto.derive_identity("test-secret", 1024, 1)
  local b = crypto.derive_identity("test-secret", 1024, 1)
  assert(eq(a:sub(), b:sub()))
  assert(eq(a:public_key(), b:public_key()))
  local sig = a:sign_request("request body")
  assert(eq(true, crypto.verify_request(a:public_key(), sig, a:sub(), "request body")))
end)

test("encrypt and decrypt, bound to associated data", function ()
  local id = crypto.derive_identity("test-secret", 1024, 1)
  local key = crypto.derive_key("test-secret", id)
  local ciphertext = key:encrypt("hello", "sub:id-1")
  assert(eq("hello", key:decrypt(ciphertext, "sub:id-1")))
  local out, msg = key:decrypt(ciphertext, "sub:id-2")
  assert(eq(nil, out))
  assert(eq("decryption failed", msg))
end)

test("subkeys are domain separated", function ()
  local id = crypto.derive_identity("test-secret", 1024, 1)
  local key = crypto.derive_key("test-secret", id)
  local db = key:derive("db")
  local search = key:derive("search")
  assert(eq(db:bytes(), key:derive("db"):bytes()))
  local ciphertext = db:encrypt("hello")
  assert(eq("hello", db:decrypt(ciphertext)))
  assert(eq(nil, search:decrypt(ciphertext)))
end)

test("generated passphrases are diceware and validate", function ()
  assert(eq(true, crypto.validate(crypto.generate())))
  assert(eq(false, crypto.validate("invalid-words-here-now-test-foo")))
end)

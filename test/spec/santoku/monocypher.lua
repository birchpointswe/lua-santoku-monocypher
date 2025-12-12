local test = require("santoku.test")

local crypto = require("santoku.monocypher")

local err = require("santoku.error")
local assert = err.assert

test("derive_identity", function ()
  local id = crypto.derive_identity("test-secret-passphrase-123")
  assert(id ~= nil)
  assert(type(id:sub()) == "string")
  assert(type(id:public_key()) == "string")
end)

test("derive_identity deterministic", function ()
  local id1 = crypto.derive_identity("test-secret")
  local id2 = crypto.derive_identity("test-secret")
  assert(id1:sub() == id2:sub())
  assert(id1:public_key() == id2:public_key())
end)

test("identity sign and export", function ()
  local id = crypto.derive_identity("test-secret")
  local sig = id:sign("hello world")
  assert(type(sig) == "string")
  assert(#sig > 0)
  local exported = id:export()
  assert(type(exported) == "table")
  assert(exported.sub ~= nil)
  assert(exported.salt ~= nil)
  assert(exported.signing_key ~= nil)
  assert(exported.public_key ~= nil)
end)

test("import_identity roundtrip", function ()
  local id1 = crypto.derive_identity("test-secret")
  local exported = id1:export()
  local id2 = crypto.import_identity(exported)
  assert(id1:sub() == id2:sub())
  assert(id1:public_key() == id2:public_key())
  assert(id1:sign("test") == id2:sign("test"))
end)

test("import_key roundtrip", function ()
  local id = crypto.derive_identity("test-secret")
  local key1 = crypto.derive_key("test-secret", id)
  local exported = key1:export()
  local key2 = crypto.import_key(exported)
  assert(key1:export() == key2:export())
end)

test("encrypt decrypt roundtrip", function ()
  local id = crypto.derive_identity("test-secret")
  local key = crypto.derive_key("test-secret", id)
  local plaintext = "hello world"
  local ciphertext = key:encrypt(plaintext)
  assert(ciphertext ~= plaintext)
  local decrypted = key:decrypt(ciphertext)
  assert(decrypted == plaintext)
end)

test("encrypt decrypt empty string", function ()
  local id = crypto.derive_identity("test-secret")
  local key = crypto.derive_key("test-secret", id)
  local plaintext = ""
  local ciphertext = key:encrypt(plaintext)
  local decrypted = key:decrypt(ciphertext)
  assert(decrypted == plaintext)
end)

test("decrypt wrong key fails", function ()
  local id1 = crypto.derive_identity("secret1")
  local key1 = crypto.derive_key("secret1", id1)
  local id2 = crypto.derive_identity("secret2")
  local key2 = crypto.derive_key("secret2", id2)
  local ciphertext = key1:encrypt("test")
  local result, errmsg = key2:decrypt(ciphertext)
  assert(result == nil)
  assert(errmsg == "decryption failed")
end)

test("sign_request and verify_request", function ()
  local id = crypto.derive_identity("test-secret")
  local body = "request body"
  local sig = id:sign_request(body)
  assert(type(sig) == "string")
  local ok, err = crypto.verify_request(id:public_key(), sig, id:sub(), body)
  assert(ok == true, err)
end)

test("verify_request wrong signature fails", function ()
  local id = crypto.derive_identity("test-secret")
  local body = "request body"
  local id2 = crypto.derive_identity("other-secret")
  local sig2 = id2:sign_request(body)
  local ok, errmsg = crypto.verify_request(id:public_key(), sig2, id:sub(), body)
  assert(ok == nil)
  assert(errmsg == "invalid_signature")
end)

test("generate passphrase", function ()
  local secret = crypto.generate()
  assert(type(secret) == "string")
  local words = {}
  for w in secret:gmatch("[^-]+") do
    words[#words + 1] = w
  end
  assert(#words == 6)
end)

test("validate passphrase", function ()
  local secret = crypto.generate()
  assert(crypto.validate(secret) == true)
end)

test("validate strong password", function ()
  assert(crypto.validate("Sh0rt!Pass") == false)
  assert(crypto.validate("ThisIsALongPassword1!") == true)
end)

test("validate invalid passphrase", function ()
  assert(crypto.validate("invalid-words-here-now-test-foo") == false)
end)

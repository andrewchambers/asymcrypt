
# XXX Can this be a template?
# We assert at runtime that our manual size matches our C size.
type crypto_hash_sha256_state = array[104, byte]
block:
  var csize_crypto_hash_sha256_state {.header: "sodium.h", importc: "sizeof(crypto_hash_sha256_state)".}: cint
  assert((sizeof crypto_hash_sha256_state) == csize_crypto_hash_sha256_state)

template NACLConstant (name, value: untyped): untyped = 
  const name {.inject.} = value
  const v = name
  block:
    var name {.inject, header: "sodium.h"}: cint
    assert(v == name) 

NACLConstant(crypto_box_PUBLICKEYBYTES, 32)
NACLConstant(crypto_box_SECRETKEYBYTES, 32)
NACLConstant(crypto_box_ZEROBYTES, 32)
NACLConstant(crypto_box_BOXZEROBYTES, 16)
NACLConstant(crypto_box_NONCEBYTES, 24)
NACLConstant(crypto_sign_PUBLICKEYBYTES, 32)
NACLConstant(crypto_sign_SECRETKEYBYTES, 64)
NACLConstant(crypto_sign_BYTES, 64)
NACLConstant(crypto_hash_sha256_BYTES, 32)

type
  BoxNonce = array[crypto_box_NONCEBYTES, byte]

proc crypto_hash_sha256_init(state: pointer): void {.header: "sodium.h", importc.}
proc crypto_hash_sha256_update(state: pointer, buf:  pointer, n: cint): void {.header: "sodium.h", importc.}
proc crypto_hash_sha256_final(state: pointer, buf:  pointer): void {.header: "sodium.h", importc.}
proc crypto_box_keypair(pk, sk: pointer): cint {.header: "sodium.h", importc.}
proc crypto_box(c, m: pointer, mlen: csize, n, pk, sk: pointer): cint {.header: "sodium.h", importc.}
proc crypto_box_open(m, c: pointer, clen: csize, n, pk, sk: pointer): cint {.header: "sodium.h", importc.}
proc crypto_sign_keypair(pk, sk: pointer): cint {.header: "sodium.h", importc.}
proc crypto_sign(s: pointer, slen: csize, m: pointer, mlen: csize, sk: pointer): cint {.header: "sodium.h", importc.}
proc crypto_sign_open(m: pointer, mlen: csize, s: pointer, slen: csize, pk: pointer): cint {.header: "sodium.h", importc.}
proc randombytes_buf(buf: pointer, size: csize): void {.header: "sodium.h", importc.}

proc sha256Init(): crypto_hash_sha256_state =
  crypto_hash_sha256_init(addr result)
  return result

proc sha256Update[T](state: var crypto_hash_sha256_state, p: ptr T): void =
  crypto_hash_sha256_update(addr state, p, cast[cint](sizeof p))

proc sha256Update(state: var crypto_hash_sha256_state, p: pointer, n: int): void =
  crypto_hash_sha256_update(addr state, p, cast[cint](n))

proc sha256Final(state: var crypto_hash_sha256_state): array[crypto_hash_sha256_BYTES, byte] =
  crypto_hash_sha256_final(addr state, addr result)

proc randomSecretBoxNonce(): BoxNonce =
  randombytes_buf(cast [ptr cuchar](addr result), sizeof result)
  return result

proc inc(n: var BoxNonce): void =
  for i in 0..n.len:
    if n[i] == 255:
      n[i] = 0
    else:
      n[i] += 1
      break


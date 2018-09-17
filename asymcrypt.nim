import algorithm, streams, os, system


template NACLConstant (name, value: untyped): untyped = 
  const name {.inject.} = value
  const v = name
  block:
    var name {.inject, header: "sodium.h"}: cint
    assert(v == name) 

NACLConstant(crypto_box_PUBLICKEYBYTES, 32)
NACLConstant(crypto_box_SECRETKEYBYTES, 32)
NACLConstant(crypto_sign_PUBLICKEYBYTES, 32)
NACLConstant(crypto_sign_SECRETKEYBYTES, 64)

type
  Key = tuple [publicEncBytes: array[crypto_box_PUBLICKEYBYTES, byte],
               secretEncBytes: array[crypto_box_SECRETKEYBYTES, byte],
               publicSigBytes: array[crypto_sign_PUBLICKEYBYTES, byte],
               secretSigBytes: array[crypto_sign_SECRETKEYBYTES, byte]]
type
  PubKey = tuple [encBytes: array[crypto_box_PUBLICKEYBYTES, byte],
                  sigBytes: array[crypto_sign_PUBLICKEYBYTES, byte]]

proc crypto_box_keypair(pk, sk:  ptr cuchar): cint {.importc.}
proc crypto_sign_keypair(pk, sk:  ptr cuchar): cint {.importc.}

proc wipeKey(k: ref Key): void =
  # don't know if nim optimises this away.
  k.secretEncBytes.fill(0)
  k.secretSigBytes.fill(0)

proc readPtr[T](f: Stream, p: ptr T): void =
  let sz = sizeof p[]
  let n = readData(f, p, sz)
  if n != sz:
    raise

const magic_len = 9
var magic = "asymcrypt"
var magic_arr = cast[ptr array[magic_len, char]](addr magic)[]

proc readHeader(f: Stream, version, ty: uint16): void =
  var buf: array[magic_len+4, byte]
  readPtr(f, addr buf)

  if cast[ptr array[magic_len, char]](addr buf)[] == magic_arr:
    raise

  if ((cast[uint16](buf[magic_len+0]) shl 8) or cast[uint16](buf[magic_len+1])) != version:
    raise
  
  if ((cast[uint16](buf[magic_len+2]) shl 8) or cast[uint16](buf[magic_len+3])) != ty:
    raise

proc readKey(f: Stream, k: ref Key): void =
  readHeader(f, 2, 0)
  readPtr(f, addr k.publicEncBytes)
  readPtr(f, addr k.secretEncBytes)
  readPtr(f, addr k.publicSigBytes)
  readPtr(f, addr k.secretSigBytes)

proc readPubKey(f: Stream, k: ref PubKey): void =
  readHeader(f, 2, 1)
  readPtr(f, addr k.encBytes)
  readPtr(f, addr k.sigBytes)

proc naclCheck(v: cint): void =
  if v != 0:
    raise

proc newKey(): ref Key =
  result = new(Key)
  naclCheck(crypto_box_keypair(
      cast[ptr cuchar](addr result.publicEncBytes[0]),
      cast[ptr cuchar](addr result.secretEncBytes[0])
    ))
  naclCheck(crypto_sign_keypair(
      cast[ptr cuchar](addr result.publicSigBytes[0]),
      cast[ptr cuchar](addr result.secretSigBytes[0])
    ))
  return

proc pubKey(k: ref Key): PubKey =
  result.encBytes = k.publicEncBytes
  result.sigBytes = k.publicSigBytes
  return

proc writeBEU16(f: Stream, n: uint16) = 
  let buf = [cast[byte]((n and 0xff00) shr 8), cast[byte](n and 0xff)]
  write(f, buf)

proc writeHeader(f: Stream, t: uint16) =
  write(f, "asymcrypt")
  writeBEU16(f, 2)
  writeBEU16(f, t)

proc writeKey(f: Stream, k: ref Key) =
  writeHeader(f, 0)
  write(f, k.publicEncBytes)
  write(f, k.secretEncBytes)
  write(f, k.publicSigBytes)
  write(f, k.secretSigBytes)
  flush(f)

proc writePubKey(f: Stream, k: PubKey) =
  writeHeader(f, 1)
  write(f, k.encBytes)
  write(f, k.sigBytes)
  flush(f)

# Commands

proc help(): void = 
  include "help.inc.nim"
  quit(QuitFailure)

if paramCount() < 1:
  help()
else:
  case paramStr(1)
  of "k", "key":
    let outStream = newFileStream(stdout)
    var k = newKey()
    writeKey(outStream, k)
    wipeKey(k)
  of "p", "pubkey":
    let inStream = newFileStream(stdin)
    let outStream = newFileStream(stdout)
    var k = new Key
    readKey(inStream, k)
    let pk = pubKey(k)
    writePubKey(outStream, pk)
    wipeKey(k)
  of "s", "sign":
    echo "sign"
  of "v", "verify":
    echo "verify"
  of "e", "encrypt":
    echo "encrypt"
  of "d", "decrypt":
    echo "decrypt":
  else:
    help()

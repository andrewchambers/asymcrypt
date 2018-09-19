import algorithm, streams, os, system

include "nacl.nim"

# TODO
# - Load keys etc from disk
# - Info command
# - Use precompute
# - Proper exception/error types
# - Annotate api with exceptions
# - Remove useless nulls from encrypted stream

type
  Key = tuple [publicEncBytes: array[crypto_box_PUBLICKEYBYTES, byte],
               secretEncBytes: array[crypto_box_SECRETKEYBYTES, byte],
               publicSigBytes: array[crypto_sign_PUBLICKEYBYTES, byte],
               secretSigBytes: array[crypto_sign_SECRETKEYBYTES, byte]]
  
  PubKey = tuple [encBytes: array[crypto_box_PUBLICKEYBYTES, byte],
                  sigBytes: array[crypto_sign_PUBLICKEYBYTES, byte]]
  
  KeyID = array[crypto_hash_sha256_BYTES, byte]

  Signature = tuple [signedBy: KeyID,
                     signedSha256: array[crypto_hash_sha256_BYTES + crypto_sign_BYTES, byte]]


proc readToPtr[T](f: Stream, p: ptr T): void =
  let sz = sizeof p[]
  let n = readData(f, p, sz)
  if n != sz:
    raise

const magic_len = 9
var magic = "asymcrypt"
var magic_arr = cast[ptr array[magic_len, char]](addr magic)[]

proc makeU16(hi, lo: byte): uint16 =
  return (cast[uint16](hi) shl 8)  or cast[uint16](lo)

proc readHeader(f: Stream, version, ty: uint16): void =
  var buf: array[magic_len+4, byte]
  readToPtr(f, addr buf)

  if cast[ptr array[magic_len, char]](addr buf)[] == magic_arr:
    raise

  if makeU16(buf[magic_len+0], buf[magic_len+1]) != version:
    raise
  
  if makeU16(buf[magic_len+2], buf[magic_len+3]) != ty:
    raise

proc readKey(f: Stream, k: ref Key): void =
  readHeader(f, 2, 0)
  readToPtr(f, addr k.publicEncBytes)
  readToPtr(f, addr k.secretEncBytes)
  readToPtr(f, addr k.publicSigBytes)
  readToPtr(f, addr k.secretSigBytes)

proc readPubKey(f: Stream): PubKey =
  readHeader(f, 2, 1)
  readToPtr(f, addr result.encBytes)
  readToPtr(f, addr result.sigBytes)

proc readSignature(f: Stream): Signature =
  readHeader(f, 2, 2)
  readToPtr(f, addr result.signedBy)
  readToPtr(f, addr result.signedSha256)

proc naclCheck(v: cint): void =
  if v != 0:
    raise

proc newKey(): ref Key =
  result = new(Key)
  naclCheck(crypto_box_keypair(
      addr result.publicEncBytes,
      addr result.secretEncBytes
    ))
  naclCheck(crypto_sign_keypair(
      addr result.publicSigBytes,
      addr result.secretSigBytes
    ))
  return

proc wipeKey(k: ref Key): void =
  # don't know if nim optimises this away.
  k.secretEncBytes.fill(0)
  k.secretSigBytes.fill(0)

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

proc writePubKey(f: Stream, k: PubKey) =
  writeHeader(f, 1)
  write(f, k.encBytes)
  write(f, k.sigBytes)

proc writeSignature(f: Stream, s: Signature) =
  writeHeader(f, 2)
  write(f, s.signedBy)
  write(f, s.signedSha256)

proc keyID(k: PubKey): array[crypto_hash_sha256_BYTES, byte] =
  var k = k
  var sha = sha256Init()
  sha256Update(sha, addr k.encBytes)
  sha256Update(sha, addr k.sigBytes)
  return sha256Final(sha)

proc keyID(k: ref Key): array[crypto_hash_sha256_BYTES, byte] =
  return keyId(pubKey(k))

const
  MESSAGE_SIZE = 16384

assert MESSAGE_SIZE > crypto_box_ZEROBYTES
assert MESSAGE_SIZE < 0xffff

proc encrypt(inStream, outStream: Stream, to: var PubKey): void =
  var
    n: int
    plainText: array[MESSAGE_SIZE, byte]
    cipherText: array[MESSAGE_SIZE, byte]
    nonce = randomSecretBoxNonce()
    ephemeralKey = newKey()

  writeHeader(outStream, 3)
  write(outStream, keyID(to))
  write(outStream, ephemeralKey.publicEncBytes)
  write(outStream, nonce)

  while true:
    # 0..crypto_box_ZEROBYTES must be zero required by nacl api
    for i in 0..crypto_box_ZEROBYTES-1:
      plainText[i] = 0

    let readSize = sizeof(plainText) - crypto_box_ZEROBYTES - 2
    n = readData(inStream, addr plainText[crypto_box_ZEROBYTES+2], readSize)
    plainText[crypto_box_ZEROBYTES] = cast[byte]((n and 0xff00) shr 8)
    plainText[crypto_box_ZEROBYTES+1] = cast[byte](n and 0xff)
    naclcheck(crypto_box(addr cipherText, addr plainText, sizeof plainText, addr nonce, addr to.encBytes, addr ephemeralKey.secretEncBytes))
    write(outStream, cipherText)
    inc nonce

    if n < readSize:
      break

proc decrypt(inStream, outStream: Stream, forKey: ref Key): void = 
  var
    forKeyID: array[crypto_hash_sha256_BYTES, byte]
    ephemeralKeyBytes: array[crypto_box_PUBLICKEYBYTES, byte]
    plainText: array[MESSAGE_SIZE, byte]
    cipherText: array[MESSAGE_SIZE, byte]
    nonce: array[crypto_box_NONCEBYTES, byte]

  readHeader(inStream, 2, 3)
  readToPtr(inStream, addr forKeyID)
  readToPtr(inStream, addr ephemeralKeyBytes)
  readToPtr(inStream, addr nonce)
  
  if forKeyID != keyID(pubKey(forKey)):
    raise

  while true:
    readToPtr(inStream, addr cipherText)
    # 0..crypto_box_BOXZEROBYTES-1 must be zero required by nacl api
    for i in 0..crypto_box_BOXZEROBYTES-1:
      cipherText[i] = 0
    naclCheck(crypto_box_open(addr plainText, addr cipherText, sizeof cipherText, addr nonce, addr ephemeralKeyBytes, addr forKey.secretEncBytes))
    let sz = cast[int](makeU16(plainText[crypto_box_ZEROBYTES], plainText[crypto_box_ZEROBYTES+1]))
    if (sz+crypto_box_ZEROBYTES+2) > sizeof plainText:
      raise
    writeData(outStream, addr plainText[crypto_box_ZEROBYTES+2], sz)
    if (sz+crypto_box_ZEROBYTES+2) != sizeof plainText:
      break
    inc nonce

proc hashStream(f: Stream): array[crypto_hash_sha256_BYTES, byte] =
  var 
    n: int
    buf: array[4096, byte]
    sha = sha256Init()

  while true:
    readToPtr(f, addr buf)
    n = readData(f, addr buf, sizeof buf)
    sha256Update(sha, addr buf, n)
    if n != sizeof buf:
      break

  return sha256Final(sha)

proc signSha256(h: var array[crypto_hash_sha256_BYTES, byte], k: var ref Key): Signature =
  result.signedBy = keyID(k)
  naclcheck crypto_sign(addr result.signedSha256, sizeof result.signedSha256, addr h, sizeof h, addr k.secretSigBytes)

proc verifySig(s: var Signature, h: var array[crypto_hash_sha256_BYTES, byte], k: var PubKey): void =
  var actual: array[crypto_hash_sha256_BYTES, byte]
  if keyID(k) != s.signedBy:
    raise
  naclcheck crypto_sign_open(addr actual, sizeof actual, addr s.signedSha256, sizeof s.signedSha256, addr k.sigBytes)
  if actual != h:
    raise

proc sign(inStream, outStream: Stream, k: var ref Key): void =
  var 
    h = hashStream(inStream)
    sig = signSha256(h, k)
  writeSignature(outStream, sig)

proc verify(inStream: Stream, sig: var Signature, k: var PubKey): void =
  var 
    h = hashStream(inStream)

  verifySig(sig, h, k)

# Commands

proc help(): void = 
  include "help.inc.nim"
  quit(QuitFailure)

let inStream = newFileStream(stdin)
let outStream = newFileStream(stdout)

if paramCount() < 1:
  help()
else:
  case paramStr(1)
  of "k", "key":
    var k = newKey()
    defer: wipeKey(k)
    writeKey(outStream, k)
  of "p", "pubkey":
    var k = new Key
    readKey(inStream, k)
    defer: wipeKey(k)
    let pk = pubKey(k)
    writePubKey(outStream, pk)
  of "s", "sign":
    var k = new Key
    readKey(inStream, k)
    defer: wipeKey(k)
    sign(inStream, outStream, k)
  of "v", "verify":
    var pk = readPubKey(inStream)
    var s = readSignature(inStream)
    verify(inStream, s, pk)
  of "e", "encrypt":
    var pk = readPubKey(inStream)
    encrypt(inStream, outStream, pk)
  of "d", "decrypt":
    var k = new Key
    readKey(inStream, k)
    defer: wipeKey(k)
    decrypt(inStream, outStream, k)
  of "i", "info":
    echo "info":
  else:
    help()

flush outStream
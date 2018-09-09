% asymcrypt_formats(5)
% Andrew Chambers
% 2018

# ASYMCRYPT FORMATS

All base constants come from the NACL cryptographic api.

## Private key version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(0)
keyid:         byte[keyid_len=16]
pubenckey:     byte[crypto_box_pk_len]
secenckey:     byte[crypto_box_sk_len]
pubsigkey:     byte[crypto_sign_pk_len]
secsigkey:     byte[crypto_sign_sk_len]
```

## Public key version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(1)
keyid:         byte[keyid_len]
pubenckey:     byte[crypto_box_pk_len]
pubsigkey:     byte[crypto_sign_pk_len]
```

## Signature version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(2)
keyid:         byte[keyid_len]
signature:     byte[crypto_hash_sha256_BYTES + crypto_sign_BYTES]
```

where crypto_sign_open(signature, pubsigkey) == sha256(data_stream)

## Cipher text version 1 format

```
magic:            "asymcrypt"
version:          be_u16(1)
type:             be_u16(3)
keyid:            byte[keyid_len]
nonce:            byte[crypto_box_NONCEBYTES]
ephemeral_pubkey: byte[crypto_box_pk_len]
(
	message: byte[msgsize=16384]
)+
```

where message is:

```
padding: byte[crypto_box_BOXZEROBYTES]
ciphertext: byte[msgsize-crypto_box_BOXZEROBYTES]
```

where crypto_box_open(message, nonce + msg_index, ephemeral_pubkey, secenckey) is:

```
padding: byte[crypto_box_ZEROBYTES]
msglen: be_u16
msg: byte[msglen]
... unused bytes till msgsize
```

The last message in the stream will have an underutilized msglen.


# SEE ALSO

**asymcrypt(1)**

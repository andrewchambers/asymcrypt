% asymcrypt(3)
% Andrew Chambers
% 2018

# Private key version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(0)
keyid:         byte[keyid_len]
pubenckey:     byte[crypto_box_pk_len]
secenckey:     byte[crypto_box_sk_len]
pubsigkey:     byte[crypto_sign_pk_len]
secsigkey:     byte[crypto_sign_sk_len]
```

# Public key version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(1)
keyid:         byte[keyid_len]
pubenckey:     byte[crypto_box_pk_len]
pubsigkey:     byte[crypto_sign_pk_len]
```

# Signature version 1 format

```
magic:         "asymcrypt"
version:       be_u16(1)
type:          be_u16(2)
keyid:         byte[keyid_len]
signature:     byte[crypto_hash_sha256_BYTES + crypto_sign_BYTES]
```

# Cipher text version 1 format

```
magic:            "asymcrypt"
version:          be_u16(1)
type:             be_u16(2)
keyid:            byte[keyid_len]
ivnonce:          byte[crypto_box_NONCEBYTES]
ephemeral_pubkey: byte[crypto_box_pk_len]
(
	message: byte[msgsize=16384];
)+
```

where message is:

```
padding: byte[crypto_box_BOXZEROBYTES];
ciphertext: byte[msgsize-crypto_box_BOXZEROBYTES];
```

where crypto_box_open(message, nonce + msg_index, ephemeral_crypto_box_pk, crypto_box_sk) is:

```
padding: byte[crypto_box_ZEROBYTES];
msglen: be_u16;
msg: byte[msglen];
... unsued bytes till msgsize
```


# SEE ALSO

**asymcrypt(1)**

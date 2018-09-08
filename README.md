% asymcrypt(3)
% Andrew Chambers
% 2018

# NAME

asymcrypt - A tool for asymmetric cryptography.

# SYNOPSIS

Generate public or private keys, sign, verify, encrypt or decrypt data.

# USAGE

```
asymcrypt - asymmetric cryptography

asymcrypt k(ey) > secret.key
asymcrypt p(ubkey) < secret.key > public.key
asymcrypt e(ncrypt) -p public.key < plain.txt > encrypted.txt
asymcrypt d(ecrypt) -s secret.key < plain.txt > encrypted.txt
asymcrypt s(ign) -s secret.key < something > something.sig
asymcrypt v(erify) -p public.key -sig something.sig < something
asymcrypt i(nfo) < encrypted.txt
asymcrypt i(nfo) < secret.key
asymcrypt i(nfo) < public.key
asymcrypt i(nfo) < something.sig

All commands exit with rc > 0 on error 0 on success.

On error a single line is printed to stderr.

On success no output is generated except for the requested data.

Encrypt and sign reject world readable secret keys.

When decrypting, only verified data is sent to stdout.

When decrypting, a truncated data stream results in error.
```

### info command output

secret key
```
secretkey V1 KEYID
```
public key
```
publickey V1 KEYID
```
signature
```
signature V1 KEYID
```
ciphertext
```
ciphertext V1 KEYID
```

# SEE ALSO

**asymcrypt_formats(5)**

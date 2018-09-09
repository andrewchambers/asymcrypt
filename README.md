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
asymcrypt p(ubkey) secret.key > public.key
asymcrypt e(ncrypt) public.key < plain.txt > encrypted.txt
asymcrypt e(ncrypt) <(cat public.key plain.txt) > encrypted.txt
asymcrypt d(ecrypt) secret.key < plain.txt > encrypted.txt
asymcrypt d(ecrypt) secret.key <(cat secret.key plain.txt) > encrypted.txt
asymcrypt s(ign) secret.key < something > something.sig
asymcrypt s(ign) <(cat secret.key something) > something.sig
asymcrypt v(erify) public.key something.sig < something
asymcrypt v(erify) public.key <(cat something.sig something)
asymcrypt v(erify) <(cat public.key something.sig something)
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

The info command outputs a single line with 3 fields

$VERSION $TYPE $KEYID

example:

  V1 secretkey KEYID
  V1 publickey KEYID
  V1 signature KEYID
  V1 ciphertext KEYID
```


# SEE ALSO

**asymcrypt_formats(5)**

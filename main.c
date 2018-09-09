#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEYID_BYTES 32
/* must fit inside u16 */
#define MESSAGE_SIZE 16384

#define TYPE_SECRETKEY 0
#define TYPE_PUBLICKEY 1
#define TYPE_SIG 2
#define TYPE_CIPHERTEXT 3
#define TYPE_END 4

unsigned char key_id[KEYID_BYTES];
unsigned char crypto_box_pk[crypto_box_PUBLICKEYBYTES];
unsigned char crypto_box_sk[crypto_box_SECRETKEYBYTES];
unsigned char ephemeral_crypto_box_pk[crypto_box_PUBLICKEYBYTES];
unsigned char ephemeral_crypto_box_sk[crypto_box_SECRETKEYBYTES];
unsigned char crypto_sign_pk[crypto_sign_PUBLICKEYBYTES];
unsigned char crypto_sign_sk[crypto_sign_SECRETKEYBYTES];
unsigned char sha256[crypto_hash_sha256_BYTES];
unsigned char nonce[crypto_box_NONCEBYTES];
crypto_hash_sha256_state sha256_state;
unsigned char signed_sha256[crypto_hash_sha256_BYTES + crypto_sign_BYTES];
unsigned long long signed_sha256_len;

#define die(msg)                                                               \
  do {                                                                         \
    fprintf(stderr, msg);                                                      \
    exit(1);                                                                   \
  } while (0)

void write_buf(unsigned char *buf, size_t n) {
  if (fwrite(buf, 1, n, stdout) != n) {
    die("error writing output\n");
  }
}

void write_u16(int16_t type) {
  unsigned char buf[2];
  buf[0] = (type >> 8) & 0xff;
  buf[1] = type & 0xff;
  write_buf(buf, sizeof(buf));
}

void write_hdr(int16_t type) {
  unsigned char *ident = (unsigned char *)"asymcrypt";
  write_buf(ident, strlen("asymcrypt"));
  // version
  write_u16(1);
  write_u16(type);
}

void must_read_buf(FILE *f, unsigned char *buf, size_t n) {
  if (fread(buf, 1, n, f) != n) {
    if (feof(f))
      die("unexpected end of input");
    else
      die("error reading input\n");
  }
}

int read_buf(FILE *f, unsigned char *buf, size_t n) {
  int nread = fread(buf, 1, n, f);
  if (nread != n)
    if (!feof(f))
      die("an error occured");
  return nread;
}

void read_hdr(FILE *f, int16_t *version, int16_t *type) {
  unsigned char buf[9 + 2 + 2];
  must_read_buf(f, buf, sizeof(buf));

  if (strncmp((const char *)buf, "asymcrypt", 9) != 0)
    die("not a valid asymcrypt object\n");

  *version = (int16_t)(buf[9] << 8) | buf[10];
  *type = (int16_t)(buf[11] << 8) | buf[12];

  if (*version != 1)
    die("unsupported version\n");

  if (*type < 0 || *type >= TYPE_END)
    die("unknown data type\n");
}

void read_secret_key(FILE *f) {
  int16_t version;
  int16_t type;

  read_hdr(f, &version, &type);

  if (version != 1)
    die("unknown key version\n");

  if (type != TYPE_SECRETKEY)
    die("input data is not a asymcrypt secret key\n");

  must_read_buf(f, key_id, sizeof(key_id));
  must_read_buf(f, crypto_box_pk, sizeof(crypto_box_pk));
  must_read_buf(f, crypto_box_sk, sizeof(crypto_box_sk));
  must_read_buf(f, crypto_sign_pk, sizeof(crypto_sign_pk));
  must_read_buf(f, crypto_sign_sk, sizeof(crypto_sign_sk));
}

void read_public_key(FILE *f) {
  int16_t version;
  int16_t type;

  read_hdr(f, &version, &type);

  if (version != 1)
    die("unknown key version\n");

  if (type != TYPE_PUBLICKEY)
    die("input data is not a asymcrypt public key\n");

  must_read_buf(f, key_id, sizeof(key_id));
  must_read_buf(f, crypto_box_pk, sizeof(crypto_box_pk));
  must_read_buf(f, crypto_sign_pk, sizeof(crypto_sign_pk));
}

void read_sig(FILE *f) {
  int16_t version;
  int16_t type;
  unsigned char buf[2];

  read_hdr(f, &version, &type);

  if (version != 1)
    die("unknown signature version\n");

  if (type != TYPE_SIG)
    die("input data is not a asymcrypt signature\n");

  must_read_buf(f, key_id, sizeof(key_id));
  must_read_buf(f, buf, sizeof(buf));
  signed_sha256_len = (long long unsigned int)(buf[0] << 8) | buf[1];

  if (signed_sha256_len > sizeof(signed_sha256))
    die("bad signature length\n");

  must_read_buf(f, signed_sha256, signed_sha256_len);
}

void cmd_key() {
  write_hdr(TYPE_SECRETKEY);
  if (crypto_box_keypair(crypto_box_pk, crypto_box_sk) != 0)
    die("error generating crypto_box keypair\n");
  if (crypto_sign_keypair(crypto_sign_pk, crypto_sign_sk) != 0)
    die("error generating crypto_sign keypair\n");

  randombytes_buf(key_id, sizeof(key_id));

  write_buf(key_id, sizeof(key_id));
  write_buf(crypto_box_pk, sizeof(crypto_box_pk));
  write_buf(crypto_box_sk, sizeof(crypto_box_sk));
  write_buf(crypto_sign_pk, sizeof(crypto_sign_pk));
  write_buf(crypto_sign_sk, sizeof(crypto_sign_sk));
}

void assert_sk_perms(char *secretkey) {
  struct stat buffer;
  if (stat(secretkey, &buffer))
    die("error checking key permissions\n");

  if ((buffer.st_mode & 0007) != 0)
    die("secret key is world accessible\n");
}

void cmd_pubkey(char *secretkey) {

  if (secretkey) {
    assert_sk_perms(secretkey);

    FILE *f = fopen(secretkey, "rb");
    if (!f)
      die("error opening secret key\n");

    read_secret_key(f);

    if (fclose(f))
      die("unable to close key");
  } else {
    read_secret_key(stdin);
  }

  write_hdr(TYPE_PUBLICKEY);
  write_buf(key_id, sizeof(key_id));
  write_buf(crypto_box_pk, sizeof(crypto_box_pk));
  write_buf(crypto_sign_pk, sizeof(crypto_sign_pk));
}

void hash_stdin() {
  crypto_hash_sha256_init(&sha256_state);

  // XXX swap everything to unistd read/write?
  // extra copy from that buf.
  unsigned char buf[4096];
  while (1) {
    int n = read_buf(stdin, buf, sizeof(buf));

    crypto_hash_sha256_update(&sha256_state, buf, n);

    if (n != sizeof(buf))
      break;
  }

  crypto_hash_sha256_final(&sha256_state, sha256);
}

void cmd_sign(char *secretkey) {

  if (secretkey) {
    assert_sk_perms(secretkey);

    FILE *f = fopen(secretkey, "rb");
    if (!f)
      die("error opening secret key\n");

    read_secret_key(f);

    if (fclose(f))
      die("unable to close key");
  } else {
    read_secret_key(stdin);
  }

  hash_stdin();

  crypto_sign(signed_sha256, &signed_sha256_len, sha256, sizeof(sha256),
              crypto_sign_sk);

  write_hdr(TYPE_SIG);
  write_buf(key_id, sizeof(key_id));
  write_u16((int16_t)signed_sha256_len);
  write_buf(signed_sha256, signed_sha256_len);
}

void cmd_verify(char *publickey, char *sigfile) {

  if (strlen(publickey)) {
    FILE *f = fopen(publickey, "rb");
    if (!f)
      die("error opening public key\n");

    read_public_key(f);

    if (fclose(f))
      die("unable to close key");
  } else {
    read_public_key(stdin);
  }

  if (strlen(sigfile)) {
    FILE *f = fopen(sigfile, "rb");
    if (!f)
      die("error opening secret key\n");

    read_sig(f);

    if (fclose(f))
      die("unable to close sig\n");
  } else {
    read_sig(stdin);
  }

  hash_stdin();

  unsigned char m[sizeof(signed_sha256)];
  unsigned long long mlen;

  if (crypto_sign_open(m, &mlen, signed_sha256, signed_sha256_len,
                       crypto_sign_pk) != 0)
    die("signature failed\n");

  if (mlen != sizeof(sha256))
    die("signature lengths differ\n");

  if (memcmp(m, sha256, sizeof(sha256)) != 0)
    die("signature differs\n");
}

void increment_nonce() {
  for (int i = 0; i < sizeof(nonce); i++) {
    int next = (nonce[i] + 1) & 0xff;
    nonce[i] = next;
    if (next != 0)
      break;
  }
}

void cmd_encrypt(char *publickey) {

  if (strlen(publickey)) {
    FILE *f = fopen(publickey, "rb");
    if (!f)
      die("error opening public key\n");

    read_public_key(f);

    if (fclose(f))
      die("unable to close key\n");
  } else {
    read_public_key(stdin);
  }

  randombytes_buf(nonce, sizeof(nonce));
  if (crypto_box_keypair(ephemeral_crypto_box_pk, ephemeral_crypto_box_sk) !=
      0) {
    die("error generating ephemeral crypto_box keypair\n");
    exit(1);
  }

  write_hdr(TYPE_CIPHERTEXT);
  write_buf(key_id, sizeof(key_id));
  write_buf(ephemeral_crypto_box_pk, sizeof(ephemeral_crypto_box_pk));
  write_buf(nonce, sizeof(nonce));

  unsigned char buf[MESSAGE_SIZE];
  unsigned char out_buf[sizeof(buf)];

  for (int i = 0; i < sizeof(out_buf); i++)
    out_buf[i] = 0;
  for (int i = 0; i < sizeof(buf); i++)
    buf[i] = 0;

  while (1) {
    size_t n_to_read = sizeof(buf) - crypto_box_ZEROBYTES - 2;
    size_t n = read_buf(stdin, buf + crypto_box_ZEROBYTES + 2, n_to_read);

    buf[crypto_box_ZEROBYTES + 0] = (n >> 8) & 0xff;
    buf[crypto_box_ZEROBYTES + 1] = n & 0xff;

    if (crypto_box(out_buf, buf, sizeof(buf), nonce, crypto_box_pk,
                   ephemeral_crypto_box_sk) != 0)
      die("error encrypting message\n");

    write_buf(out_buf, sizeof(out_buf));

    increment_nonce();

    if (n < n_to_read)
      break;
  }
}

void cmd_decrypt(char *secretkey) {

  if (strlen(secretkey)) {
    assert_sk_perms(secretkey);

    FILE *f = fopen(secretkey, "rb");
    if (!f)
      die("error opening public key\n");

    read_secret_key(f);

    if (fclose(f))
      die("unable to close key\n");
  } else {
    read_secret_key(stdin);
  }

  int16_t version;
  int16_t type;

  read_hdr(stdin, &version, &type);

  if (version != 1)
    die("unknown ciphertext version\n");

  if (type != TYPE_CIPHERTEXT)
    die("input data is not a asymcrypt ciphertext\n");

  unsigned char stream_keyid[sizeof(key_id)];
  must_read_buf(stdin, stream_keyid, sizeof(stream_keyid));

  if (memcmp(stream_keyid, key_id, sizeof(key_id)) != 0)
    die("stream and secret key do not match\n");

  must_read_buf(stdin, ephemeral_crypto_box_pk,
                sizeof(ephemeral_crypto_box_pk));
  must_read_buf(stdin, nonce, sizeof(nonce));

  unsigned char in_buf[MESSAGE_SIZE];
  unsigned char out_buf[sizeof(in_buf)];

  while (1) {
    must_read_buf(stdin, in_buf, sizeof(in_buf));

    for (int i = 0; i < crypto_box_BOXZEROBYTES; i++)
      if (in_buf[i] != 0)
        die("message has corrupt padding\n");

    if (crypto_box_open(out_buf, in_buf, sizeof(in_buf), nonce,
                        ephemeral_crypto_box_pk, crypto_box_sk) != 0)
      die("error decrypting stream\n");

    size_t data_size = (out_buf[crypto_box_ZEROBYTES + 0] << 8) |
                       out_buf[crypto_box_ZEROBYTES + 1];
    write_buf(out_buf + crypto_box_ZEROBYTES + 2, data_size);

    if (data_size + crypto_box_ZEROBYTES + 2 != MESSAGE_SIZE)
      break;

    increment_nonce();
  }
}

void help() {
#include "help.inc"
  exit(1);
}

int main(int argc, char **argv) {
  if (!freopen(NULL, "rb", stdin))
    die("unable to switch stdin to binary mode\n");

  if (!freopen(NULL, "wb", stdout))
    die("unable to switch stdin to binary mode\n");

  if (setvbuf(stdin, 0, _IOFBF, 4096) != 0)
    die("unable to set stdin buffering\n");

  if (setvbuf(stdout, 0, _IOFBF, 4096) != 0)
    die("unable to set stdout buffering\n");

  if (argc <= 1)
    help();

#define CMD(cmd) (strcmp(argv[1], cmd) == 0 || strncmp(argv[1], cmd, 1) == 0)
  if (CMD("key")) {
    cmd_key();
  } else if (CMD("pubkey")) {
    if (argc == 2)
      cmd_pubkey(0);
    else if (argc == 3)
      cmd_pubkey(argv[2]);
    else
      die("bad argument count for pubkey command\n");
  } else if (CMD("sign")) {
    if (argc == 2)
      cmd_sign(0);
    else if (argc == 3)
      cmd_sign(argv[2]);
    else
      die("bad argument count for sign command\n");
  } else if (CMD("verify")) {
    if (argc == 2)
      cmd_verify(0, 0);
    else if (argc == 3)
      cmd_verify(argv[2], 0);
    else if (argc == 4)
      cmd_verify(argv[2], argv[3]);
    else
      die("bad argument count for verify command\n");
  } else if (CMD("encrypt")) {
    if (argc == 2)
      cmd_encrypt(0);
    else if (argc == 3)
      cmd_encrypt(argv[2]);
    else
      die("bad argument count for encrypt command\n");
  } else if (CMD("decrypt")) {
    if (argc == 2)
      cmd_decrypt(0);
    else if (argc == 3)
      cmd_decrypt(argv[2]);
    else
      die("bad argument count for decrypt command\n");
  } else if (CMD("info")) {
    die("unimplemented\n");
  } else {
    help();
  }
#undef CMD

  if (fflush(stdout) != 0)
    die("error flushing output\n");

  if (fflush(stderr) != 0)
    die("error flushing error output\n");

  return 0;
}
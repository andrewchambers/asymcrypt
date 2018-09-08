#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEYID_BYTES 32

#define TYPE_SECRETKEY 0
#define TYPE_PUBLICKEY 1
#define TYPE_SIG 2
#define TYPE_END 3

int has_sk = 0;

unsigned char key_id[KEYID_BYTES];
unsigned char crypto_box_pk[crypto_box_PUBLICKEYBYTES];
unsigned char crypto_box_sk[crypto_box_SECRETKEYBYTES];
unsigned char crypto_sign_pk[crypto_sign_PUBLICKEYBYTES];
unsigned char crypto_sign_sk[crypto_sign_SECRETKEYBYTES];
unsigned char sha256[crypto_hash_sha256_BYTES];
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

void write_i16(int16_t type) {
  unsigned char buf[2];
  buf[0] = (type >> 8) & 0xff;
  buf[1] = type & 0xff;
  write_buf(buf, sizeof(buf));
}

void write_hdr(int16_t type) {
  unsigned char *ident = (unsigned char *)"asymcrypt";
  write_buf(ident, strlen("asymcrypt"));
  // version
  write_i16(1);
  // type
  write_i16(type);
}

void must_read_buf(FILE *f, unsigned char *buf, size_t n) {
  if (fread(buf, 1, n, f) != n)
    die("error reading input\n");
}

int read_buf(FILE *f, unsigned char *buf, size_t n) {
  int nread = fread(buf, 1, sizeof(buf), stdin);
  if (nread != sizeof(buf))
    if (!feof(stdin))
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

  has_sk = 1;
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

  has_sk = 0;
}

void read_sig(FILE *f) {
  int16_t version;
  int16_t type;
  unsigned char buf[2];

  read_hdr(f, &version, &type);

  if (version != 1)
    die("unknown key version\n");

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
  if (crypto_box_keypair(crypto_box_pk, crypto_box_sk) != 0) {
    die("error generating crypto_box keypair\n");
    exit(1);
  }
  if (crypto_sign_keypair(crypto_sign_pk, crypto_sign_sk) != 0) {
    die("error generating crypto_sign keypair\n");
    exit(1);
  }

  randombytes_buf(key_id, sizeof(key_id));

  write_buf(key_id, sizeof(key_id));
  write_buf(crypto_box_pk, sizeof(crypto_box_pk));
  write_buf(crypto_box_sk, sizeof(crypto_box_sk));
  write_buf(crypto_sign_pk, sizeof(crypto_sign_pk));
  write_buf(crypto_sign_sk, sizeof(crypto_sign_sk));
}

void cmd_pubkey() {
  read_secret_key(stdin);

  write_hdr(TYPE_PUBLICKEY);
  write_buf(key_id, sizeof(key_id));
  write_buf(crypto_box_pk, sizeof(crypto_box_pk));
  write_buf(crypto_sign_pk, sizeof(crypto_sign_pk));
}

void assert_sk_perms(char *secretkey) {
  struct stat buffer;
  if (stat(secretkey, &buffer))
    die("error checking key permissions\n");

  if ((buffer.st_mode & 0007) != 0)
    die("secret key is world accessible\n");
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

  assert_sk_perms(secretkey);

  FILE *f = fopen(secretkey, "rb");
  if (!f)
    die("error opening secret key\n");

  read_secret_key(f);

  if (fclose(f))
    die("unable to close key");

  hash_stdin();

  crypto_sign(signed_sha256, &signed_sha256_len, sha256, sizeof(sha256),
              crypto_sign_sk);

  write_hdr(TYPE_SIG);
  write_buf(key_id, sizeof(key_id));
  write_i16((int16_t)signed_sha256_len);
  write_buf(signed_sha256, signed_sha256_len);
}

void cmd_verify(char *publickey, char *sigfile) {

  FILE *f = fopen(publickey, "rb");
  if (!f)
    die("error opening secret key\n");

  read_public_key(f);

  if (fclose(f))
    die("unable to close key");

  f = fopen(sigfile, "rb");
  if (!f)
    die("error opening secret key\n");

  read_sig(f);

  if (fclose(f))
    die("unable to close sig\n");

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

void help() {
#include "help.inc"
  exit(1);
}

int main(int argc, char **argv) {
  if (argc <= 1)
    help();

#define CMD(cmd) (strcmp(argv[1], cmd) == 0 || strncmp(argv[1], cmd, 1) == 0)
  if (CMD("key")) {
    cmd_key();
  } else if (CMD("pubkey")) {
    cmd_pubkey();
  } else if (CMD("sign")) {
    if (argc != 3)
      help();
    cmd_sign(argv[2]);
  } else if (CMD("verify")) {
    if (argc != 4)
      help();
    cmd_verify(argv[2], argv[3]);
  } else if (CMD("encrypt")) {
    die("unimplemented\n");
  } else if (CMD("decrypt")) {
    die("unimplemented\n");
  } else if (CMD("info")) {
    die("unimplemented\n");
  } else {
    help();
  }
#undef CMD

  if (fflush(stdout) != 0) {
    die("error flushing output\n");
  }

  return 0;
}
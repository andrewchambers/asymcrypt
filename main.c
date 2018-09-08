#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYID_BYTES 32

#define TYPE_SECRETKEY 0
#define TYPE_PUBLICKEY 1
#define TYPE_END 2

int has_sk = 0;

unsigned char key_id[KEYID_BYTES];
unsigned char crypto_box_pk[crypto_box_PUBLICKEYBYTES];
unsigned char crypto_box_sk[crypto_box_SECRETKEYBYTES];
unsigned char crypto_sign_pk[crypto_sign_PUBLICKEYBYTES];
unsigned char crypto_sign_sk[crypto_sign_SECRETKEYBYTES];

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

void read_buf(FILE *f, unsigned char *buf, size_t n) {
  if (fread(buf, 1, n, f) != n)
    die("error reading input\n");
}

void read_hdr(FILE *f, int16_t *version, int16_t *type) {
  unsigned char buf[9 + 2 + 2];
  read_buf(f, buf, sizeof(buf));

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

  read_buf(f, key_id, sizeof(key_id));
  read_buf(f, crypto_box_pk, sizeof(crypto_box_pk));
  read_buf(f, crypto_box_sk, sizeof(crypto_box_sk));
  read_buf(f, crypto_sign_pk, sizeof(crypto_sign_pk));
  read_buf(f, crypto_sign_sk, sizeof(crypto_sign_sk));

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

  read_buf(f, key_id, sizeof(key_id));
  read_buf(f, crypto_box_pk, sizeof(crypto_box_pk));
  read_buf(f, crypto_sign_pk, sizeof(crypto_sign_pk));

  has_sk = 0;
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
    die("unimplemented\n");
  } else if (CMD("verify")) {
    die("unimplemented\n");
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
    exit(1);
  }

  return 0;
}
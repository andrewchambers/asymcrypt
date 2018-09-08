#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

#define TYPE_PRIVKEY 0

int has_sk = 0;
int has_pk = 0;

unsigned char crypto_box_pk[crypto_box_PUBLICKEYBYTES];
unsigned char crypto_box_sk[crypto_box_SECRETKEYBYTES];
unsigned char crypto_sign_pk[crypto_sign_PUBLICKEYBYTES];
unsigned char crypto_sign_sk[crypto_sign_SECRETKEYBYTES];

void
xwrite(unsigned char *buf, size_t n)
{
	if (fwrite(buf, 1, n, stdout) != n) {
		fprintf(stderr, "error writing output\n");
		exit(1);
	}
}

void
help()
{
	#include "help.inc"
	exit(1);
}

void
write_i16(int16_t type)
{
	unsigned char buf[2];
	buf[0] = (type>>8) & 0xff;
	buf[1] = type & 0xff;
	xwrite(buf, sizeof(buf));
}


void
write_hdr(int16_t type)
{
	char *ident = "asymcrypt";
	xwrite(ident, strlen("asymcrypt"));
	// version
	write_i16(1);
	// type
	write_i16(type);
}

void
cmd_key()
{
	write_hdr(TYPE_PRIVKEY);
    if (crypto_box_keypair(crypto_box_pk, crypto_box_sk) != 0) {
    	fprintf(stderr, "error generating crypto_box keypair\n");
		exit(1);
    }
    if (crypto_sign_keypair(crypto_sign_pk, crypto_sign_sk) != 0) {
    	fprintf(stderr, "error generating crypto_sign keypair\n");
		exit(1);
    }
    xwrite(crypto_box_pk, sizeof(crypto_box_pk));
    xwrite(crypto_box_sk, sizeof(crypto_box_sk));
    xwrite(crypto_sign_pk, sizeof(crypto_sign_pk));
    xwrite(crypto_sign_sk, sizeof(crypto_sign_sk));
}

int main(int argc, char **argv) {
	if (argc <= 1)
		help();

	#define CMD(cmd) (strcmp(argv[1], cmd) == 0 || strncmp(argv[1], cmd, 1) == 0)
	if (CMD("key")) {
		cmd_key();
	} else if (CMD("pubkey")) {
		fprintf(stderr, "unimplemented\n");
		exit(1);
	} else if (CMD("sign")) {
		fprintf(stderr, "unimplemented\n");
		exit(1);
	} else if (CMD("verify")) {
		fprintf(stderr, "unimplemented\n");
		exit(1);
	} else if (CMD("key")) {
		fprintf(stderr, "unimplemented\n");
		exit(1);
	} else if (CMD("key")) {
		fprintf(stderr, "unimplemented\n");
		exit(1);
	} else {
		help();
	}
	#undef CMD

	return 0;
}
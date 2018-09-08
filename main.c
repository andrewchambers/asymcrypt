#include <stdio.h>
#include <stdlib.h>

typedef struct {

} acrypt_secret_key;

typedef struct {

} acrypt_public_key;

int
load_priv_key(char *path, acrypt_secret_key *sk)
{
	return 0;
}

void
free_secret_key(acrypt_secret_key *sk)
{
	return;
}

int
load_pub_key(char *path)
{
	return 0;
}

int
acrypt_get_pub_key(acrypt_secret_key *sk, acrypt_public_key *pk)
{
	return 0;
}

void
help()
{
	#include "help.inc"
	exit(1);
}

int main() {
	help();
	return 0;
}
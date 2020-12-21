/*
 * Demo on how to use /dev/crypto device for ciphering.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "testhelper.h"

#define	DATA_SIZE	(2*1024)
#define AUTH_SIZE       32
#define	BLOCK_SIZE	16
#define	KEY_SIZE	16

#define my_perror(x) {fprintf(stderr, "%s: %d\n", __func__, __LINE__); perror(x); }

static int debug = 1;

static void print_buf(char *desc, const unsigned char *buf, int size)
{
	int i;
	fputs(desc, stdout);
	for (i = 0; i < size; i++) {
		printf("%.2x", (uint8_t) buf[i]);
	}
	fputs("\n", stdout);
}

struct aes_gcm_vectors_st {
	const uint8_t *key;
	const uint8_t *auth;
	int auth_size;
	const uint8_t __attribute__ ((aligned (32))) *plaintext;
	int plaintext_size;
	const uint8_t *iv;
	const uint8_t *ciphertext;
	const uint8_t *tag;
};


/* Checks if encryption and subsequent decryption 
 * produces the same data.
 */
static int test_encrypt_decrypt(int cfd)
{
	uint8_t plaintext_raw[DATA_SIZE + 63], *plaintext;
	uint8_t ciphertext_raw[DATA_SIZE + 63], *ciphertext;
	uint8_t iv[BLOCK_SIZE];
	uint8_t key[KEY_SIZE];
	uint8_t auth[AUTH_SIZE];
	int enc_len;
	int i;

	struct session_op sess;
	struct crypt_auth_op cao;
	struct session_info_op siop;

	if (debug) {
		fprintf(stdout, "Tests on AES-GCM encryption/decryption: ");
		fflush(stdout);
	}

	memset(&sess, 0, sizeof(sess));
	memset(&cao, 0, sizeof(cao));

	memset(key, 0x33, sizeof(key));
	memset(iv, 0x03, sizeof(iv));
	memset(auth, 0xf1, sizeof(auth));

	/* Get crypto session for AES128 */
	sess.cipher = CRYPTO_AES_CCM;
	sess.keylen = KEY_SIZE;
	sess.key = key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		my_perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	siop.ses = sess.ses;
	if (ioctl(cfd, CIOCGSESSINFO, &siop)) {
		my_perror("ioctl(CIOCGSESSINFO)");
		return 1;
	}
//      printf("requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s\n",
//                      siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name);

	plaintext = (uint8_t *)buf_align(plaintext_raw, siop.alignmask);
	ciphertext = (uint8_t *)buf_align(ciphertext_raw, siop.alignmask);

	memset(plaintext, 0x15, DATA_SIZE);

	/* Encrypt data.in to data.encrypted */
	cao.ses = sess.ses;
	cao.auth_src = auth;
	cao.auth_len = sizeof(auth);
	cao.len = DATA_SIZE;
	cao.src = plaintext;
	cao.dst = ciphertext;
	cao.iv = iv;
	cao.iv_len = 12;
	cao.op = COP_ENCRYPT;
	cao.flags = 0;

	if (ioctl(cfd, CIOCAUTHCRYPT, &cao)) {
		my_perror("ioctl(CIOCAUTHCRYPT)");
		return 1;
	}

	enc_len = cao.len;
	//printf("Original plaintext size: %d, ciphertext: %d\n", DATA_SIZE, enc_len);

	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		my_perror("ioctl(CIOCFSESSION)");
		return 1;
	}

//	return 1;

//	printf("cipher:");
//	for (i = 0; i < DATA_SIZE; i++) {
//		if ((i % 30) == 0)
//			printf("\n");
//		printf("%02x ", ciphertext[i]);
//	}
//	printf("\n");

	/* Get crypto session for AES128 */
	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_AES_CCM;
	sess.keylen = KEY_SIZE;
	sess.key = key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		my_perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	/* Decrypt data.encrypted to data.decrypted */
	cao.ses = sess.ses;
	cao.auth_src = auth;
	cao.auth_len = sizeof(auth);
	cao.len = enc_len;
	cao.src = ciphertext;
	cao.dst = ciphertext;
	cao.iv = iv;
	cao.iv_len = 12;
	cao.op = COP_DECRYPT;
	cao.flags = 0;

	printf("YS: calling CIOCAUTHCRYPT cao.len=%d\n", enc_len);
	if (ioctl(cfd, CIOCAUTHCRYPT, &cao)) {
		my_perror("ioctl(CIOCAUTHCRYPT)");
		return 1;
	}

	if (cao.len != DATA_SIZE) {
		fprintf(stderr, "decrypted data size incorrect!\n");
		return 1;
	}

	/* Verify the result */
	if (memcmp(plaintext, ciphertext, DATA_SIZE) != 0) {
		fprintf(stderr,
			"FAIL: Decrypted data are different from the input data.\n");
		printf("plaintext:");
		for (i = 0; i < DATA_SIZE; i++) {
			if ((i % 30) == 0)
				printf("\n");
			printf("%02x ", plaintext[i]);
		}
		printf("decipher:");
		for (i = 0; i < DATA_SIZE; i++) {
			if ((i % 30) == 0)
				printf("\n");
			printf("%02x ", ciphertext[i]);
		}
		printf("\n");
		return 1;
	}

	/* Finish crypto session */
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		my_perror("ioctl(CIOCFSESSION)");
		return 1;
	}

	if (debug) {
		fprintf(stdout, "ok\n");
		fprintf(stdout, "\n");
	}

	return 0;
}


int main(int argc, char** argv)
{
	int fd = -1, cfd = -1;

	if (argc > 1) debug = 1;

	/* Open the crypto device */
	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		my_perror("open(/dev/crypto)");
		return 1;
	}

	/* Clone file descriptor */
	if (ioctl(fd, CRIOGET, &cfd)) {
		my_perror("ioctl(CRIOGET)");
		return 1;
	}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		my_perror("fcntl(F_SETFD)");
		return 1;
	}

	/* Run the test itself */

//	if (test_crypto(cfd))
//		return 1;

	if (test_encrypt_decrypt(cfd))
		return 1;

	/* Close cloned descriptor */
	if (close(cfd)) {
		my_perror("close(cfd)");
		return 1;
	}

	/* Close the original descriptor */
	if (close(fd)) {
		my_perror("close(fd)");
		return 1;
	}

	return 0;
}

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string>
#include <time.h>
#include <math.h>



int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key, int is_public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
	printf( "Failed to create key BIO");
	return 0;
    }
    if(is_public)
    {
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
	printf( "Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}


int private_decrypt(unsigned char * enc_data,int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}


int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

int spc_sign(unsigned char *msg, unsigned int mlen, unsigned char * key, unsigned char *out) 
{
    unsigned char hash[20];

    BN_CTX        *c;

    RSA * r = createRSA(key, 0);
    unsigned int outlen[1] = {RSA_size(r)};

    if (!(c = BN_CTX_new(  ))) return 0;
    if (!SHA1(msg, mlen, hash) || !RSA_blinding_on(r, c)) {
	BN_CTX_free(c);
	return 0;
    }
    RSA_sign(NID_sha1, hash, 20, out, outlen, r);
    RSA_blinding_off(r);
    BN_CTX_free(c);
    return *outlen;
}


int spc_verify(unsigned char *msg, unsigned int mlen, unsigned char * key, unsigned char *sig) 
{
    unsigned char hash[20];
    int ret; 
    RSA * r = createRSA(key, 1); 
    unsigned int siglen = RSA_size(r);
    if (!SHA1(msg, mlen, hash)) {
	return 0;
    }
    ret = RSA_verify(NID_sha1, hash, 20, sig, siglen, r);
    return siglen;
}



int main() {
    unsigned char plainText[1024] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
				     "l9Z67xdRaKqhujEbR3oH4GJRjZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlq\n"\
				     "PNZYPFR3yvgYg9oBLCUinnJqmLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM\n"\
				     "0VauSfUSkVKix5FVYQIDAQAB\n";

    const char plainText1[1024] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
				   "l9Z67xdRaKqhujEbR3oH4GJRjZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlq\n"\
				   "PNZYPFR3yvgYg9oBLCUinnJqmLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM\n"\
				   "0VauSfUSkVKix5FVYQIDAQAB\n";

    unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
				 "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
				 "l9Z67xdRaKqhujEbR3oH4GJRjZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlq\n"\
				 "PNZYPFR3yvgYg9oBLCUinnJqmLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM\n"\
				 "0VauSfUSkVKix5FVYQIDAQAB\n"\
				 "-----END PUBLIC KEY-----\n";

    unsigned char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
				  "MIICWwIBAAKBgQCkF9CHrKXETzkuu/1VyWEVtzF7l9Z67xdRaKqhujEbR3oH4GJR\n"\
				  "jZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlqPNZYPFR3yvgYg9oBLCUinnJq\n"\
				  "mLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM0VauSfUSkVKix5FVYQIDAQAB\n"\
				  "AoGAd/K4ihSX79IBeLoOS0EzaI5K649oRuCy6N1brXDPKKOs/kj1VavxNDIRHGAk\n"\
				  "0dNxEkA6JyY2529MtrqWyoR+V4DAQ/s1xoxEDBqbHF6x9SK3GvlXzZLdJExxl4g/\n"\
				  "NAM9Ls8RfoDi6cPYYDWa9GMpB5x4+e5+kDbp+F1MKRh9igkCQQDVNftSx/iPiCfR\n"\
				  "ze0bRh9x1fsKWewMq0UGXbw6h01fgNkXXByPJ6KfM58nxFCinyRL4LKEnc4vcQ//\n"\
				  "KWqKDda/AkEAxQZVFc1BaFHJrh7g1NzWEGLEm+S6uazY3li1p3nfRdg0H7QeYeFM\n"\
				  "v9f2m4mhjlki+GbiOYZMQ80FV8sSD4r73wJAUGiHW/TmnNrwiYNsBHkxqrDUeFbp\n"\
				  "Wu3MnlYDgt88IuRo+xJWAvcjsX66azjyYCI8ghE/whvxgprVOZnZAC+v6QJAStCq\n"\
				  "woqcibZ09Q94pJvvFW3L5r6mQRdnipb4882NgQImWNuWpehdsoOZe1p55Inog5bd\n"\
				  "1KYwk5ZorvvHses+1QJAWSt8ws23L/R7S2ZSBsDuAAD8aRuHVyReAUqnPg5eiSlf\n"\
				  "hzKw1TcxTGz611Z6HjaocrrGGdraAjem35xyZBOpcA==\n"\
				  "-----END RSA PRIVATE KEY-----\n";

    unsigned char encrypted[4098]={};
    unsigned char decrypted[4098]={};


    int batch_count = 100;
    int iter_count = 10;
    int u_c = 0;
    double generation_overhead[1000];

    unsigned char hash[20];
    BN_CTX *c;
    RSA * priKey = createRSA(privateKey, 0);
    unsigned int outlen[1] = {RSA_size(priKey)};
    unsigned int mlen = 1024;

    if (!(c = BN_CTX_new())) return 0;

    if (!SHA1(plainText, mlen, hash)) {
	BN_CTX_free(c);
	return 0;
    }


    // for public key
    RSA * pubKey = createRSA(publicKey, 1);
    int ret; 
    unsigned int siglen = RSA_size(pubKey);

    while (u_c < iter_count) {

	// one batch
	int counter = 0;
	clock_t begin, end;
	double time_spent;
	struct timespec start_high, end_high;
	uint64_t delta_us;

	// Blinding
	clock_gettime(CLOCK_MONOTONIC_RAW, &start_high);
	begin = clock();
	if (!RSA_blinding_on(pubKey, c)) return 0;
	end = clock();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end_high);
	delta_us = end_high.tv_nsec - start_high.tv_nsec;
	//delta_us = (end_high.tv_sec - start_high.tv_sec) * 1000000 + (end_high.tv_nsec - start_high.tv_nsec) / 1000;
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time spent for blinding =%ld nanoseconds\n", (long)delta_us);
	printf("Time spent for blinding =%4f seconds\n", time_spent);


	// Signing
	clock_gettime(CLOCK_MONOTONIC_RAW, &start_high);
	if (!RSA_sign(NID_sha1, hash, 20, encrypted, outlen, priKey)) return 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &end_high);
	delta_us = (end_high.tv_sec - start_high.tv_sec) * 1000000 + (end_high.tv_nsec - start_high.tv_nsec) / 1000;
	printf("Time spent for signing =%ld micorseconds\n", (long)delta_us);

	// unbliding
	clock_gettime(CLOCK_MONOTONIC_RAW, &start_high);
	RSA_blinding_off(pubKey);
	clock_gettime(CLOCK_MONOTONIC_RAW, &end_high);
	delta_us = end_high.tv_nsec - start_high.tv_nsec;
	printf("Time spent for unblinding =%ld nanoseconds\n", (long)delta_us);
	BN_CTX_free(c);

	// verifying
	clock_gettime(CLOCK_MONOTONIC_RAW, &start_high);
	if (!RSA_verify(NID_sha1, hash, 20, encrypted, siglen, pubKey)) {
	    printf("Invalid signature\n");
	    return 0;
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end_high);
	delta_us = end_high.tv_nsec - start_high.tv_nsec;
	printf("Time spent for verifying =%ld nanoseconds\n", (long)delta_us);

	// store time in the array
	generation_overhead[u_c] = time_spent;
	u_c += 1;
    }


    // determine the mean, std, median
    double mean = 0.0;
    double median = 0.0;
    double std = 0.0;

    for (int i = 0; i < iter_count; ++i) {
	mean += generation_overhead[i];
    }

    mean = mean / iter_count;
    //median = (generation_overhead[499] + generation_overhead[500]) / 2;
    for (int i = 0; i < iter_count; ++i) {
	std += (generation_overhead[i] - mean) * (generation_overhead[i] - mean);
    }
    std = sqrt(std/iter_count);
    printf("Avg. Time spent =%4f \n", mean);
    printf("Std. Time spent =%4f \n",  std);

    //printf("Decrypted Text =%s\n",decrypted);
    //printf("Decrypted Length =%d\n",decrypted_length);

}

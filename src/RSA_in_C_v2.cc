#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string>
#include <time.h>
#include <math.h>



int padding = RSA_PKCS1_PADDING;
double signing_overhead[1000];
double verification_overhead[1000];
double blinding_overhead[1000];
double unblinding_overhead[1000];
int u_c = 0;
int counter = 0;

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


int private_encrypt_with_blinding(unsigned char * from, int flen,unsigned char * key, unsigned char *to)
{

    clock_t t, t0, t1, t2, t3, t4;
    RSA * rsa = createRSA(key, 0);
    BIGNUM *f, *ret;
    int i, j, k, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    t = clock();
    if ((ctx = BN_CTX_new()) == NULL)  goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    //printf("num = %d, flen = %d...\n", num, flen);

    i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
    if (i <= 0) goto err;

    if (BN_bin2bn(buf, num, f) == NULL) goto err;

    if (BN_ucmp(f, rsa->n) >= 0)   goto err;

    //printf("blinding...");
    t0 = clock();
    rsa->blinding = RSA_setup_blinding(rsa, ctx);
    if (rsa->blinding == NULL)  goto err;
    
    if (!BN_BLINDING_convert_ex(f, NULL, rsa->blinding, ctx)) goto err;

    t1 = clock();

    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    ((rsa->p != NULL) &&
	     (rsa->q != NULL) &&
	     (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
	if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
	    goto err;
    } else {
	BIGNUM *d = BN_new();
	if (d == NULL) 
	    goto err;
	BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);

	if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
		    rsa->_method_mod_n)) {
	    BN_free(d);
	    goto err;
	}
	BN_free(d);
    }
    t2 = clock();
    //printf("unblinding...");

    if (!BN_BLINDING_invert_ex(ret, NULL, rsa->blinding, ctx))
	goto err;

    t3 = clock();


    j = BN_num_bytes(ret);
    i = BN_bn2bin(ret, &(to[num - j]));
    for (k = 0; k < (num - i); k++)
	to[k] = 0;

    r = num;
err:
    if (ctx != NULL)
	BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_cleanse(buf, num);

    t4 = clock();
    if (counter == 0) {blinding_overhead[u_c] = 0; unblinding_overhead[u_c] = 0; signing_overhead[u_c] = 0;}
    blinding_overhead[u_c] += (double)(t1 - t0) / CLOCKS_PER_SEC;
    unblinding_overhead[u_c] += (double)(t3 - t2) / CLOCKS_PER_SEC;
    signing_overhead[u_c] += (double)(t4 - t - t1 + t0 - t3 + t2) / CLOCKS_PER_SEC;
    return (r);
}

int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}



int main() {
    unsigned char plainText2[] = "MIGfMA0GCSq\n";
    const char plainText2_const[] = "MIGfMA0GCSq\n";

    unsigned char plainText[1024] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
				     "l9Z67xdRaKqhujEbR3oH4GJRjZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlq\n"\
				     "PNZYPFR3yvgYg9oBLCUinnJqmLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM\n"\
				     "0VauSfUSkVKix5FVYQIDAQAB\n";

    const char plainText_const[1024] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
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

    unsigned char  encrypted[4098]={};
    unsigned char decrypted[4098]={};


    int batch_count = 1000;
    int iter_count = 10;
    int encrypted_length, decrypted_length;


    while (u_c < iter_count) {

	// one batch

	clock_t begin, end;
	double time_spent;

	begin = clock();
	counter = 0;
	while (counter < batch_count) {
	    counter += 1;
	    // signing
	    encrypted_length = private_encrypt_with_blinding(plainText2, strlen(plainText2_const), privateKey, encrypted);
	    if(encrypted_length == -1) {
		printf("Error: Encryption Failed.\n");
		exit(0);
	    }
	    //if (counter = 0) printf("%d. encrypted message w. blinding =%s \n", u_c, encrypted);
	}
	end = clock();
	//printf("%d. Encrypted message = ", u_c);
	//for (int j = 0; j <= encrypted_length; j++) printf("0x%X, ", encrypted[j]);
	//printf("\n");

	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

	printf("%d. Encrypted length =%d, \t Encrption Time =%4f seconds. \n", u_c, encrypted_length, time_spent);

	begin = clock();
	counter = 0;
	while (counter < batch_count) {
	    counter += 1;
	    // verfication
	    decrypted_length = public_decrypt(encrypted, encrypted_length, publicKey, decrypted);
	    if(decrypted_length == -1) {
		printf("Error:  Decryption Failed.\n");
		exit(0);
	    }
	    //if (counter = 0) printf("%d. decrypted message w. blinding =%s \n", u_c, decrypted);
	}
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	//printf("%d. Decrypted message =%s \n", u_c, decrypted);
	verification_overhead[u_c] = time_spent;
	printf("%d. Decrypted length =%d, \t Decrption Time =%4f seconds. \n", u_c, decrypted_length, time_spent);

	u_c ++;
    }


  // determine the mean, std, median
  double mean[] = {0.0, 0.0, 0.0, 0.0};
  double median[] = {0.0, 0.0, 0.0, 0.0};
  double std[] = {0.0, 0.0, 0.0, 0.0};

  for (int i = 0; i < iter_count; ++i) {
    mean[0] += blinding_overhead[i]/iter_count;
    mean[1] += unblinding_overhead[i]/iter_count;
    mean[2] += signing_overhead[i]/iter_count;
    mean[3] += verification_overhead[i]/iter_count;
  }

  for (int i = 0; i < iter_count; ++i) {
    std[0] += (blinding_overhead[i] - mean[0]) * (blinding_overhead[i] - mean[0]);
    std[1] += (blinding_overhead[i] - mean[1]) * (blinding_overhead[i] - mean[1]);
    std[2] += (blinding_overhead[i] - mean[2]) * (blinding_overhead[i] - mean[2]);
    std[3] += (blinding_overhead[i] - mean[3]) * (blinding_overhead[i] - mean[3]);
  }

  std::vector<int> blinding_vector (blinding_vector, blinding_vector + 1000); 
  std::sort(blinding_vector.begin(), blinding_vector.end());
  int index = 0;
  for (std::vector<int>::iterator it=blinding_vector.begin(); it!=blinding_vector.end(); ++it) {
      if (index == 499) median[0] += *it;
      if (index == 500) median[0] += *it;
  }
  median[0] = median[0] / 2.0;
  


  //std = sqrt(std/iter_count);
  printf("Avg. Blinding Time = %4f seconds. \n", mean[0]);
  printf("Blinding Time STD= %4f seconds. \n", std[0] / iter_count);


  printf("Avg. Unblinding Time = %4f seconds. \n", mean[1]);
  printf("Avg. Signing Time = %4f seconds. \n", mean[2]);
  printf("Avg. Verfication Time = %4f seconds. \n", mean[3]);

  //printf("Decrypted Text =%s\n",decrypted);
  //printf("Decrypted Length =%d\n",decrypted_length);
  
}

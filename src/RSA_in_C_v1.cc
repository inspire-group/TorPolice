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

int public_encrypt_with_blinding(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    BN_CTX        *c;

    RSA * r = createRSA(key, 0);

    if (!(c = BN_CTX_new(  ))) return 0;
    if (!RSA_blinding_on(r, c)) {
      BN_CTX_free(c);
      return 0;
    }
    int ret = rsa_ossl_private_encrypt(data_len,data,encrypted,rsa,padding);
    RSA_blinding_off(r);
    BN_CTX_free(c);
    return ret;
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

    RSA * r = createRSA(key, 0);
    unsigned int outlen[1] = {RSA_size(r)};

    if (!SHA1(msg, mlen, hash)) {
      return 0;
    }
    RSA_sign(NID_sha1, hash, 20, out, outlen, r);
    return *outlen;
}

int spc_sign_with_blinding(unsigned char *msg, unsigned int mlen, unsigned char * key, unsigned char *out) 
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
      return ret;
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

  unsigned char  encrypted[4098]={};
  unsigned char decrypted[4098]={};


  int batch_count = 1000;
  int iter_count = 10;
  int u_c = 0;
  double generation_overhead[1000];
  int encrypted_length;
  //double verification_overhead[1000];
  //double overall_overhead[1000];
  while (u_c < iter_count) {

    // one batch
    int counter = 0;
    clock_t begin, end, end2;
    double time_spent;
    begin = clock();
    while (counter < batch_count) {
      counter += 1;
      // sign
      encrypted_length = spc_sign(plainText, strlen(plainText1), privateKey, encrypted);
      if(encrypted_length == 0)
      {
	       exit(0);
      }
    }
    end = clock();

    counter = 0;
    while (counter < batch_count) {
      counter += 1;
      // private encrypt
      encrypted_length = spc_sign_with_blinding(plainText, strlen(plainText1), privateKey, encrypted);
      if(encrypted_length == 0) exit(0);
    }
    end2 = clock();



    


    time_spent = (double)(end2 - end * 2 + begin) / CLOCKS_PER_SEC;
    //printf("%d. Encrypted message =%s \n", u_c, encrypted);
    printf("%d. Encrypted length =%d \n", u_c, encrypted_length);
    //for (int j = 0; j < encrypted_length+1; j++) printf("0x%X, ", encrypted[j]);

    unsigned char encrypted2[] = {0x6A, 0x3C, 0x1A, 0x24, 0x58, 0x90, 0x27, 0x84, 0x66, 0x72, 0x33, 0x1A, 0xE3, 0x86, 0x3F, 0x7B, 0x41, 0x8D, 0x8F, 0x17, 0x45, 0xFA, 0x46, 0xCE, 0x46, 0x43, 0x52, 0x38, 0x70, 0x8A, 0x8C, 0x88, 0x13, 0xB2, 0x26, 0x3D, 0x0, 0x9C, 0x24, 0x91, 0x4F, 0xE3, 0x57, 0x41, 0x24, 0x90, 0x41, 0x4A, 0xAE, 0xF, 0xE, 0xCA, 0x4E, 0x78, 0xD5, 0xF0, 0xAD, 0xEB, 0xC8, 0x24, 0x61, 0xF7, 0x16, 0x5E, 0x4C, 0x4C, 0x89, 0x9D, 0x34, 0x94, 0xD1, 0x7E, 0x1B, 0xF5, 0xBB, 0x90, 0x29, 0xC8, 0x68, 0xD9, 0x32, 0x1D, 0xCC, 0x30, 0x9B, 0x8F, 0xF4, 0xD4, 0x7E, 0x2E, 0x6E, 0x2A, 0xCD, 0xE0, 0xD9, 0x8E, 0xB0, 0x0, 0xD, 0xED, 0xFB, 0x6F, 0x90, 0x22, 0x4, 0x46, 0xB9, 0xD2, 0x8F, 0x4F, 0x5B, 0x6E, 0xB4, 0x8, 0xEB, 0xA7, 0x7C, 0x4D, 0x84, 0xED, 0x93, 0x80, 0xC2, 0xA2, 0x5E, 0x48, 0x98, 0x64, 0x0};
    int verified = spc_verify(plainText, strlen(plainText1), publicKey, encrypted2);
    if (verified == 0) {
       printf("verification failed.\n");
    }


    printf("\n%d. Time spent =%4f seconds\n", u_c, time_spent);

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

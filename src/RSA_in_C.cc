#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
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

/*
   void printLastError(char *msg)
   {
   char * err = malloc(130);
   ERR_load_crypto_strings();
   ERR_error_string(ERR_get_error(), err);
   printf("%s ERROR: %s\n",msg, err);
   free(err);
   }*/


int main() {
    unsigned char plainText[1024/8] = "Hello wo cao ni ma"; //key length : 1024
    const char plainText1[1024/8] = "Hello wo cao ni ma"; //key length : 1024

    /* key for 2048
       unsigned char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
       "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
       "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
       "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
       "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
       "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
       "wQIDAQAB\n"\
       "-----END PUBLIC KEY-----\n";
       */
    unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
				 "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkF9CHrKXETzkuu/1VyWEVtzF7\n"\
				 "l9Z67xdRaKqhujEbR3oH4GJRjZ2GdO3lx4MCJkxna40rTCODVIzlDYcmi9zNIdlq\n"\
				 "PNZYPFR3yvgYg9oBLCUinnJqmLOIs/oFu/MyR9Z4h9TIlhdNesfDBlfirye5iSzM\n"\
				 "0VauSfUSkVKix5FVYQIDAQAB\n"\
				 "-----END PUBLIC KEY-----\n";

    /* key for 2048
       unsigned char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
       "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
       "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
       "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
       "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
       "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
       "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
       "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
       "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
       "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
       "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
       "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
       "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
       "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
       "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
       "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
       "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
       "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
       "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
       "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
       "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
       "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
       "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
       "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
       "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
       "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
       "-----END RSA PRIVATE KEY-----\n";
       */
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
    //double verification_overhead[1000];
    //double overall_overhead[1000];
    while (u_c < iter_count) {

	// one batch
	int counter = 0;
	clock_t begin, end;
	double time_spent;
	begin = clock();
	while (counter < batch_count) {
	    counter += 1;
	    // private encrypt
	    int encrypted_length = private_encrypt(plainText, strlen(plainText1), privateKey, encrypted);
	    if(encrypted_length == -1)
	    {
		//printLastError("Private Encrypt failed");
		exit(0);
	    }
	    //printf("Encrypted length =%d\n",encrypted_length);

	    // public decrypt
	    /*
	       int decrypted_length = public_decrypt(encrypted, encrypted_length, publicKey, decrypted);
	       if(decrypted_length == -1)
	       {
	    //printLastError("Public Decrypt failed");
	    exit(0);
	    }*/
	}
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

	// store time in the array
	generation_overhead[u_c] = time_spent;
	printf("Tme: %4f\n", time_spent);
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
    std = sqrt(std/1000);


    printf("Sign overhead mean: %4f\n", mean);
    printf("Sign overhead median: %4f\n", median);
    printf("Sign overhead std: %4f\n", std);
    //printf("Decrypted Length =%d\n",decrypted_length);


    //printf("Decrypted Text =%s\n",decrypted);
    //printf("Decrypted Length =%d\n",decrypted_length);

}

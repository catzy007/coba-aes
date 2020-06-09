#ifndef MYOPENSSL_H_INCLUDED
#define MYOPENSSL_H_INCLUDED

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

void handleErrors(void);
void custHandleErrors(void);

int generateKey(unsigned int salt[], unsigned char *key_data, int nrounds, 
            unsigned char *mkey, unsigned char *miv);

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void generateIntFromHex(unsigned char *ciphertext, int ciphertext_len);

#endif
#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

int main (void)
{
    int round = 5;
    unsigned char passwd[] = "helloUsr";
    unsigned char *plaintext = (unsigned char *)"MSG:AT 1700, 16TH, SUBMARINE U-1062 AGAIN RECEIVED A TORPEDO ATTACK ";
    printf("Plaintext %ldBit:\n",strlen(plaintext)*8);
    printf("%s\n", plaintext);

    unsigned char mkey[33] = "\0"; //32+1
    unsigned char miv[33] = "\0";
    unsigned char ciphertext[4096] = "\0";
    unsigned char decryptedtext[4096] = "\0";
    int decryptedtext_len, ciphertext_len;
    
    //generate key from KDF
    generateKey(NULL, passwd, round, mkey, miv);

    //encrypt message
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), mkey, miv, ciphertext);
    printf("\nCiphertext %dBit:\n",ciphertext_len*8);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    printf("\nKey %ldBit:\n",strlen(mkey)*8);
    BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));
    printf("\nIV %ldBit:\n",strlen(miv)*8);
    BIO_dump_fp (stdout, (const char *)miv, strlen(miv));

    //generate array of integer encoded hex
    generateIntFromHex(ciphertext, ciphertext_len);

    //try to decrypt message to validate
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, mkey, miv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';
    printf("\nDecrypted text %dBit:\n",decryptedtext_len*8);
    printf("%s\n", decryptedtext);

    return 0;
}
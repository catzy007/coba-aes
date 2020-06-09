#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

int main (void)
{
    unsigned char passwd[] = "hello123";
    unsigned char *plaintext = (unsigned char *)"MSG:1)  ALBRECHT ((1062)) WAS REFUELLED BY BURGHAGEN ((219)) 28 SEPT IN #EH 70 ((11.51 N - 34.45 W 'C')) AND WAS TO REPORT WEATHER ON ENTERING BD ((AT 42.54 N)).  IN SPITE OF MANY REQUESTS HE HAS SENT NO ANSWER AND HAS NOT REACHED PORT.  NO INFO ON CAUSE OF LOSS, BUT PRESUMABLY SUNK BY A/C.";
    printf("Plaintext %ldBit:\n",strlen(plaintext)*8);
    printf("%s\n", plaintext);

    unsigned char mkey[33] = "\0"; //32+1
    unsigned char miv[33] = "\0";
    unsigned char ciphertext[4096] = "\0";
    unsigned char decryptedtext[4096] = "\0";
    int decryptedtext_len, ciphertext_len;
    
    //generate key from KDF
    generateKey(NULL, "hello123", 5, mkey, miv);

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
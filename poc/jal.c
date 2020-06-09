#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void);

int generateKey(unsigned int salt[], unsigned char *key_data, int nrounds, 
            unsigned char *mkey, unsigned char *miv);

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


void generateIntFromHex(unsigned char *ciphertext, int ciphertext_len){
    printf("\nHex to Int %d:\n",ciphertext_len);
    printf("{");
    for(int i=0; i<ciphertext_len; i++){
        //printf("%d",(int)strtol(ciphertext[i], NULL, 16));
        printf("%d",ciphertext[i]);
        if(i < ciphertext_len-1){
            printf(",");
        }
    }
    printf("}\n");
}

int main (void)
{
    /* generate key from KDF */
    unsigned char mkey[33] = "\0"; //32+1
    unsigned char miv[33] = "\0";
    // unsigned int salt[] = {12345, 54321};
    generateKey(NULL, "hello123", 5, mkey, miv);

    /* random key and iv to check false negative */
    unsigned char *wKey = (unsigned char *)"01234567890123456789012345678905";
    unsigned char *wIv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"MSG:The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128] = "\0";

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128] = "\0";

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), mkey, miv,
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext %ld:\n",strlen(ciphertext)*8);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    generateIntFromHex(ciphertext, ciphertext_len);

    /* print key and iv */
    printf("\nKey %ld:\n",strlen(mkey)*8);
    BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));

    printf("\nIV %ld:\n",strlen(miv)*8);
    BIO_dump_fp (stdout, (const char *)miv, strlen(miv));

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, mkey, miv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("\nDecrypted text is %d:\n",decryptedtext_len);
    printf("%s\n", decryptedtext);

    //==================================
    printf("\nKey:\n");
    BIO_dump_fp (stdout, (const char *)wKey, strlen(wKey));
    printf("\nIV:\n");
    BIO_dump_fp (stdout, (const char *)wIv, strlen(wIv));
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, wKey, wIv,
                                decryptedtext);
    if(decryptedtext_len == -1){
        printf("\nkey not match!\n");
    }else{
        decryptedtext[decryptedtext_len] = '\0';
        printf("\nDecrypted text is:\n");
        printf("%s\n", decryptedtext);
    }

    return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int generateKey(unsigned int salt[], unsigned char *key_data, int nrounds, unsigned char *mkey, unsigned char *miv){
    int i;
    int key_data_len = strlen(key_data);
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char *)&salt, key_data, key_data_len, nrounds, mkey, miv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
        plaintext_len = -1;
        handleErrors();
    }else{
        plaintext_len += len;
    }
    

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

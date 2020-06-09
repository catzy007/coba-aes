#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

void bruteforce(int length);
void indexToMyKey(int *idxmyKey, char *myKey, char *dict, int length);
int decryptAes(unsigned char *inputKey, unsigned int salt[], int round);
int validateMsg(const char *decryptedtext);
char* concat(const char *s1, const char *s2);

int main(int argc, char *argv[]){
    // unsigned char mkey[33] = "\0"; //32+1
    // unsigned char miv[33] = "\0";
    // generateKey(NULL, "hello123", 5, mkey, miv);
    // unsigned char ciphertext[128] = "\0";
    // unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
    // int ciphertext_len;
    // ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), mkey, miv, ciphertext);
    // printf("Ciphertext %ld:\n",strlen(ciphertext)*8);
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    // generateIntFromHex(ciphertext, ciphertext_len);

    printf("hello World!\n");
    bruteforce(3);
    return 0;
}

void bruteforce(int length){
    char dict[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"};
    int dictLen=(sizeof(dict)/sizeof(char))-1;

    char *myKey;
    myKey = malloc(sizeof(char)*length+1);
    int *idxmyKey;
    idxmyKey = malloc(sizeof(int)*length);

    //set initial state for index myKey
    for(int i=0; i<length; i++){
        idxmyKey[i] = -1;
    }

    //bruteforce algorithm
    unsigned int salt[] = {12345, 54321};
    while(1){
        // for(int i=0; i<length; i++){
        //     printf("%d ",idxmyKey[i]);
        // }
        // printf("\n");
        indexToMyKey(idxmyKey, myKey, dict, length);
        printf("%s\n",concat("hello",myKey));
        if(decryptAes(concat("hello",myKey), salt, 5) == -1){
            break;
        }

        idxmyKey[0] += 1;
        for(int i=0; i<length; i++){
            if(idxmyKey[i] > dictLen-1){
                idxmyKey[i+1] += 1;
                idxmyKey[i] = 0;
            }
        }

        if(idxmyKey[length] >= 1){
            break;
        }
    }
    
    free(myKey);
    free(idxmyKey);
}

void indexToMyKey(int *idxmyKey, char *myKey, char *dict, int length){
    for(int i=0; i<length; i++){
        if(idxmyKey[i] < 0){
            myKey[i] = '\0';
        }else{
            myKey[i] = dict[idxmyKey[i]];
        }
    }
}

int decryptAes(unsigned char *inputKey, unsigned int salt[], int round){
    unsigned char mkey[33] = "\0"; //32+1
    unsigned char miv[33] = "\0";
    generateKey(NULL, inputKey, round, mkey, miv);

    unsigned char ciphertext[128] = {237,88,33,56,210,217,167,141,232,48,84,2,86,3,138,161,134,102,129,174,10,232,200,229,48,126,187,158,195,38,42,113,44,143,5,189,158,67,89,168,49,240,24,95,227,124,212,157};
    unsigned char decryptedtext[128] = "\0";

    int decryptedtext_len, ciphertext_len;
    ciphertext_len = strlen(ciphertext);
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, mkey, miv,
                                decryptedtext);
    
    decryptedtext[decryptedtext_len] = '\0';

    if(decryptedtext_len == -1 || !validateMsg(decryptedtext)){
        return 0;
    }else{
        printf("Ciphertext %ld:\n",strlen(ciphertext)*8);
        BIO_dump_fp (stdout, (const char *)ciphertext, strlen(ciphertext));
        printf("Key %ld:\n",strlen(mkey)*8);
        BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));
        printf("IV %ld:\n",strlen(miv)*8);
        BIO_dump_fp (stdout, (const char *)miv, strlen(miv));
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
        return -1;//-1
    }
}

int validateMsg(const char *decryptedtext){
    if(decryptedtext[0]=='M' && decryptedtext[1]=='S' &&
    decryptedtext[2]=='G' && decryptedtext[3]==':'){
        return 1;
    }else{
        return 0;
    }
}

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}
#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

void bruteforce(int length, unsigned char *ciphertext, unsigned int ciphertext_len);
void indexToMyKey(int *idxMyKey, char *myKey, char *dictChar, int length);
int decryptAes(unsigned char *inputKey, int round, 
                unsigned char *ciphertext, unsigned int ciphertext_len);
int validateMsg(const char *decryptedtext);
char* concat(const char *s1, const char *s2);

int main(int argc, char *argv[]){
    printf("hello World!\n");

    unsigned char ciphertext[] = {175,3,123,102,18,50,196,232,27,216,160,166,76,183,78,160,86,211,187,79,142,50,187,103,236,204,43,214,106,248,161,126,164,164,25,121,28,228,175,74,75,14,20,254,163,106,23,69,42,182,242,93,223,209,134,233,196,67,230,1,59,102,244,59,81,136,25,159,84,128,215,113,53,164,213,165,105,49,178,231};
    unsigned int ciphertext_len = sizeof(ciphertext)/sizeof(unsigned char);
    printf("\nCiphertext %dBit:\n",ciphertext_len*8);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    bruteforce(3, ciphertext, ciphertext_len);
    return 0;
}

void bruteforce(int length, unsigned char *ciphertext, unsigned int ciphertext_len){
    char *dictWord[] = {"trustno1","jordan","buster","hello","user","secret","soccer","admin","starwars","thomas"};
    char dictChar[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"};
    // char dictChar[] = {"1234567890"};
    int dictCharLen=(sizeof(dictChar)/sizeof(char))-1;

    char *myKey;
    myKey = malloc(sizeof(char)*length+1);
    int *idxMyKey;
    idxMyKey = malloc(sizeof(int)*length);

    // printf("%ld\n\n",sizeof(dictWord)/sizeof(dictWord[0]));

    //bruteforce algorithm
    for(int j=0; j<8; j++){
        //set initial state for index myKey
        for(int i=0; i<=length; i++){
            idxMyKey[i] = -1;
        }
        while(1){
            indexToMyKey(idxMyKey, myKey, dictChar, length);
            printf("%s\n",concat(dictWord[j],myKey));
            if(decryptAes(concat(dictWord[j],myKey), 5, ciphertext, ciphertext_len) == -1){
                goto finish;
            }

            idxMyKey[0] += 1;
            for(int i=0; i<length; i++){
                if(idxMyKey[i] > dictCharLen-1){
                    idxMyKey[i+1] += 1;
                    idxMyKey[i] = 0;
                }
            }

            if(idxMyKey[length] >= 1){
                break;
            }
        }
    }

    finish:
    
    free(myKey);
    free(idxMyKey);
}

void indexToMyKey(int *idxMyKey, char *myKey, char *dictChar, int length){
    for(int i=0; i<length; i++){
        if(idxMyKey[i] < 0){
            myKey[i] = '\0';
        }else{
            myKey[i] = dictChar[idxMyKey[i]];
        }
    }
}

int decryptAes(unsigned char *inputKey, int round, unsigned char *ciphertext, unsigned int ciphertext_len){
    unsigned char mkey[33] = "\0"; //32+1
    unsigned char miv[33] = "\0";
    generateKey(NULL, inputKey, round, mkey, miv);

    unsigned char decryptedtext[1024] = "\0";

    int decryptedtext_len;
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, mkey, miv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    if(decryptedtext_len == -1 || !validateMsg(decryptedtext)){
        // printf("Key %ldBit:\n",strlen(mkey)*8);
        // BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));
        // decryptedtext[4] = '\0';
        // printf("Decrypted text %dBit:\n",decryptedtext_len*8);
        // printf("%s\n", decryptedtext);
        return 0;
    }else{
        printf("Ciphertext %ldBit:\n",strlen(ciphertext)*8);
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        printf("Key %ldBit:\n",strlen(mkey)*8);
        BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));
        printf("IV %ldBit:\n",strlen(miv)*8);
        BIO_dump_fp (stdout, (const char *)miv, strlen(miv));
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text %dBit:\n",decryptedtext_len*8);
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

char *concat(const char *s1, const char *s2){
    char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}
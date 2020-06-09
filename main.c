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

    unsigned char ciphertext[] = {73,144,229,244,46,171,125,237,222,107,150,3,132,122,76,130,185,115,44,47,18,68,198,164,192,67,136,86,182,199,140,90,250,182,110,236,116,244,244,91,186,201,196,20,148,118,198,74,120,133,244,241,135,39,185,177,54,48,178,181,107,9,156,118,212,229,115,114,69,97,29,53,230,188,184,185,56,69,63,22,189,143,88,208,0,25,5,36,193,144,137,44,157,117,194,145,223,135,194,119,231,129,97,118,93,217,227,185,20,231,111,40,31,242,14,83,34,205,65,227,169,204,35,48,1,203,151,255,125,179,216,157,146,180,74,242,133,229,214,25,236,210,89,173,3,177,28,180,141,194,104,170,32,67,25,255,134,32,217,226,16,230,244,14,48,10,33,28,219,57,195,193,127,9,242,121,204,78,131,204,196,8,57,86,177,59,185,116,242,11,76,97,86,69,118,227,196,167,66,161,172,106,106,6,190,56,161,175,245,241,74,45,231,159,128,182,183,255,165,38,120,205,149,215,180,111,160,47,21,79,119,191,232,210,68,85,108,250,250,175,131,217,213,144,35,82,201,216,85,156,0,231,246,72,171,122,157,73,22,232,215,53,240,71,98,53,14,8,234,38,164,103,100,105,102,43,142,176,3,102,237,3,226,54,55,135,74,200,249,134,248,237,117,98,85,229,77,87,17,76,246,164,156,159};
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
    unsigned char mkey[32] = "\0"; //32+1
    unsigned char miv[16] = "\0";
    generateKey(NULL, inputKey, round, mkey, miv);


    int mkeylen = sizeof(mkey)/sizeof(mkey[0]);
    int mivlen = sizeof(miv)/sizeof(miv[0]);
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
        printf("Key %dBit:\n",mkeylen*8);
        BIO_dump_fp (stdout, (const char *)mkey, mkeylen);
        printf("IV %dBit:\n",mivlen*8);
        BIO_dump_fp (stdout, (const char *)miv, mivlen);
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
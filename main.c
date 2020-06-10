#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

/*
Begin bruteforce
    Input
        Character length to bruteforce -> int
        Chipertext -> unsigned *char
        Chipertext length -> unsigned int
    Output
        Iteration of bruteforce
*/
void bruteforce(int length, unsigned char *ciphertext, unsigned int ciphertext_len);

/*
Convert array of progress index to progress text
    Input
        Progress Index -> *char
        Dictionary -> *char
        Character length -> int
    Output
        Progress text -> *char
*/
void indexToMyKey(int *idxMyKey, char *myKey, char *dictChar, int length);

/*
Decrypt chipertext using given key
    Input
        Input key -> unsigned *char
        n round -> int
        Chipertext -> unsigned *char
        Chipertext length -> unsigned int
    Output
        Message not valid or decrypt failed -> 0 -> return
        Message valid -> -1 -> return
        Dump of chipertext, key, iv, message
*/
int decryptAes(unsigned char *inputKey, int round, 
                unsigned char *ciphertext, unsigned int ciphertext_len);

/*
Validate given message by looking for `MSG:`
    Input
        Decrpted text -> const *char
    Output
        Message valid -> 1 -> return
        Message invalid -> 0 -> return
*/
int validateMsg(const char *decryptedtext);

/*
Join two message together
    Input
        First message -> const *char
        Second  message -> const *char
    Output
        Joined Message -> *char -> return
*/
char* concat(const char *s1, const char *s2);

int main(int argc, char *argv[]){
    //just random text to make sure this works
    printf("hello World!\n");

    //put your chipertext below
    unsigned char ciphertext[] = {248,141,230,133,187,53,151,45,152,116,142,74,189,62,150,8,120,60,15,62,34,169,255,14,181,177,159,241,144,127,137,146,139,189,156,145,18,106,157,240,222,14,251,62,56,34,71,39,192,183,164,17,10,156,6,122,174,149,17,248,8,254,22,199,160,93,32,231,96,222,147,101,245,253,252,85,100,88,35,16,192,128,165,178,187,109,37,177,25,28,29,13,204,158,196,190,68,147,24,93,217,246,114,201,60,165,6,229,18,186,174,73,135,147,208,45,30,84,24,194,134,59,48,106,174,82,127,184,71,47,215,175,11,204,215,63,115,244,169,154,13,181,68,26,53,218,185,102,72,32,205,220,107,217,198,99,133,79,129,255,86,225,13,13,43,205,200,212,86,32,198,156,47,207,168,21,254,218,176,151,36,175,27,47,225,179,198,55,160,28,36,33,93,64,165,59,143,89,214,151,31,182,12,204,202,149,195,124,172,145,21,224,196,173,54,85,228,88,218,91,66,85,148,11,67,205,197,229,193,144,33,237,64,33,13,233,217,56,157,233,95,226,142,1,53,72,196,240,8,8,30,244,173,13,181,44,197,15,202,229,186,131,253,5,158,54,52,82,25,217,52,70,95,2,172,58,23,156,40,206,176,173,68,128,187,41,82,139,231,112,46,228,39,235,35,210,179,135,57,216,35,151,200,169};
    unsigned int ciphertext_len = sizeof(ciphertext)/sizeof(unsigned char);
    printf("\nCiphertext %dBit:\n",ciphertext_len*8);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    //begin bruteforce
    bruteforce(3, ciphertext, ciphertext_len);
    return 0;
}

void bruteforce(int length, unsigned char *ciphertext, unsigned int ciphertext_len){
    //this is dictionary section
    char *dictWord[] = {"trustno1","jordan","buster","hello","user","secret","soccer","admin","starwars","thomas"};
    char dictChar[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"};
    // char dictChar[] = {"1234567890"};
    int dictWordLen=sizeof(dictWord)/sizeof(dictWord[0]);
    int dictCharLen=(sizeof(dictChar)/sizeof(char))-1;

    //allocate memory to hold key
    char *myKey;
    myKey = malloc(sizeof(char)*length+1);
    int *idxMyKey;
    idxMyKey = malloc(sizeof(int)*length);

    // printf("%ld\n\n",sizeof(dictWord)/sizeof(dictWord[0]));

    //bruteforce algorithm
    for(int j=0; j<dictWordLen; j++){
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

    //jump point
    finish:
    
    //clean some memory
    free(myKey);
    free(idxMyKey);
}

int decryptAes(unsigned char *inputKey, int round, unsigned char *ciphertext, unsigned int ciphertext_len){
    //generate key from KDF
    unsigned char mkey[32] = "\0"; //32+1
    unsigned char miv[16] = "\0";
    generateKey(NULL, inputKey, round, mkey, miv);

    //some variables
    int mkeylen = sizeof(mkey)/sizeof(mkey[0]);
    int mivlen = sizeof(miv)/sizeof(miv[0]);
    unsigned char decryptedtext[1024] = "\0";

    //decryption process
    int decryptedtext_len;
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, mkey, miv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    if(decryptedtext_len == -1 || !validateMsg(decryptedtext)){
        //debug
        // printf("Key %ldBit:\n",strlen(mkey)*8);
        // BIO_dump_fp (stdout, (const char *)mkey, strlen(mkey));
        // decryptedtext[4] = '\0';
        // printf("Decrypted text %dBit:\n",decryptedtext_len*8);
        // printf("%s\n", decryptedtext);
        return 0;
    }else{
        //print the msg after decrypt
        printf("Ciphertext %dBit:\n",ciphertext_len*8);
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

//convert index to MyKey
void indexToMyKey(int *idxMyKey, char *myKey, char *dictChar, int length){
    for(int i=0; i<length; i++){
        if(idxMyKey[i] < 0){
            myKey[i] = '\0';
        }else{
            myKey[i] = dictChar[idxMyKey[i]];
        }
    }
}

//because this is crude implementation, i need this
int validateMsg(const char *decryptedtext){
    if(decryptedtext[0]=='M' && decryptedtext[1]=='S' &&
    decryptedtext[2]=='G' && decryptedtext[3]==':'){
        return 1;
    }else{
        return 0;
    }
}

//some function i found in stackoverflow
char *concat(const char *s1, const char *s2){
    char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}
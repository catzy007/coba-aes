#include <stdio.h>
#include <stdlib.h>
#include "myopenssl.h"

void bruteforce(int length);
void indexToChiper(int *idxChiper, char *chiper, char *dict, int length);

int main(int argc, char *argv[]){
    printf("hello World!\n");
    bruteforce(4);
    return 0;
}

void bruteforce(int length){
    char dict[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"};
    int dictLen=(sizeof(dict)/sizeof(char))-1;

    char *chiper;
    chiper = malloc(sizeof(char)*length+1);
    int *idxChiper;
    idxChiper = malloc(sizeof(int)*length);

    //set initial state for index chiper
    for(int i=0; i<length; i++){
        idxChiper[i] = -1;
    }

    //bruteforce algorithm
    while(1){
        // for(int i=0; i<length; i++){
        //     printf("%d ",idxChiper[i]);
        // }
        // printf("\n");
        indexToChiper(idxChiper, chiper, dict, length);
        printf("%s\n",chiper);

        idxChiper[0] += 1;
        for(int i=0; i<length; i++){
            if(idxChiper[i] > dictLen-1){
                idxChiper[i+1] += 1;
                idxChiper[i] = 0;
            }
        }

        if(idxChiper[length] >= 1){
            break;
        }
    }
    
    free(chiper);
    free(idxChiper);
}

void indexToChiper(int *idxChiper, char *chiper, char *dict, int length){
    for(int i=0; i<length; i++){
        if(idxChiper[i] < 0){
            chiper[i] = '\0';
        }else{
            chiper[i] = dict[idxChiper[i]];
        }
    }
}
#!/bin/bash
gcc -c myopenssl.c -lcrypto
gcc -c generatechiper.c
gcc myopenssl.o generatechiper.o -o main -lcrypto
./main
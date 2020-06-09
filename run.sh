#!/bin/bash
gcc -c myopenssl.c -lcrypto
gcc -c main.c
gcc myopenssl.o main.o -o main -lcrypto
./main
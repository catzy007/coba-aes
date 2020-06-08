#!/bin/bash
gcc -c myopenssl.c -lcrypto
gcc -c main.c
gcc *.o -o main -lcrypto
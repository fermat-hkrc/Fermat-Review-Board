#!/bin/bash
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 poc.c -o poc
./poc

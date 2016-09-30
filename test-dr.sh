#!/bin/bash -x

FILE_PATH="/home/frdeso/projets/dummy_debug/main"
./dr -a $FILE_PATH 0x400666
./dr -b $FILE_PATH main
./dr -b $FILE_PATH main+12
./dr -b $FILE_PATH washington
./dr -b $FILE_PATH saguenay
./dr -b $FILE_PATH toronto
./dr -b $FILE_PATH montreal
./dr -c $FILE_PATH main.c:9
./dr -c $FILE_PATH main.c:12
./dr -c $FILE_PATH main.c:17
./dr -c $FILE_PATH main.c:23
./dr -c $FILE_PATH main.c:46
./dr -c $FILE_PATH object.c:7
./dr -c $FILE_PATH external.h:6

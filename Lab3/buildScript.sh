#!/bin/bash

FILENAME="encoder"
gcc -o $FILENAME $FILENAME.c

dumpshellcode () {
    for i in $(/home/kali/Desktop/UNI/MALW/Lab/Lab3/$FILENAME virus_code.bin | grep "^\""); do
        echo -n $i;
    done;
}

SHELLCODE=$(dumpshellcode)

RUNNER=Shellcode64
TMP=tmp.c
echo "#define SHELLCODE $SHELLCODE" > $TMP
cat $RUNNER.c >> $TMP
gcc -o $RUNNER $TMP
rm $TMP

/home/kali/Desktop/UNI/MALW/Lab/Lab3/$RUNNER
#!/bin/bash

FILENAME="text_output"
nasm -f elf32 $FILENAME.asm -o $FILENAME.o
ld -melf_i386 -o $FILENAME $FILENAME.o
rm $FILENAME.o

dumpshellcode () {
    for i in $(objdump -d $1 |grep "^ " |cut -f2); do
        echo -n '\x'$i;
    done;
}

SHELLCODE=$(dumpshellcode $FILENAME)

RUNNER=shellcode_runner
TMP=tmp.c
echo "#define SHELLCODE \"$SHELLCODE\"" > $TMP
cat $RUNNER.c >> $TMP
gcc -m32 -o $RUNNER $TMP
rm $TMP

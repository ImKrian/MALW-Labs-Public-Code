#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#define NUMBER_JUNK_INSTR 31
#define NUMBER_DECODER_INSTR 14
 
 unsigned char useless[][5] = {
	{"\x90"}, 				/* nop */
	{"\x4d\x31\xd2"}, 		/* xor r10,r10 */
	{"\x4d\x31\xdb"}, 		/* xor r10,r10 */
	{"\x4d\x31\xe4"}, 		/* xor r10,r10 */
	{"\x4d\x31\xed"}, 		/* xor r10,r10 */
	{"\x4d\x31\xf6"}, 		/* xor r10,r10 */
	{"\x4d\x31\xff"}, 		/* xor r10,r10 */
	{"\x49\xc1\xea\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe2\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xc1\xeb\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe3\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xc1\xec\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe4\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xc1\xed\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe5\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xc1\xee\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe6\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xc1\xef\x08"}, 	/* shr r10, 0x8 */
	{"\x49\xc1\xe7\x08"}, 	/* shl r10, 0x8 */
	{"\x49\xff\xc2"}, 		/* inc r10 */
	{"\x49\xff\xca"}, 		/* dec r10 */
	{"\x49\xff\xc3"}, 		/* inc r10 */
	{"\x49\xff\xcb"}, 		/* dec r10 */
	{"\x49\xff\xc4"}, 		/* inc r10 */
	{"\x49\xff\xcc"}, 		/* dec r10 */
	{"\x49\xff\xc5"}, 		/* inc r10 */
	{"\x49\xff\xcd"}, 		/* dec r10 */
	{"\x49\xff\xc6"}, 		/* inc r10 */
	{"\x49\xff\xce"}, 		/* dec r10 */
	{"\x49\xff\xc7"}, 		/* inc r10 */
	{"\x49\xff\xcf"}}; 		/* dec r10 */
 
 unsigned char decoder_matrix[][5] = {
	 {"\x4d\x31\xc0"},          /* xor    %r8,%r8               */
	 {"\x41\xb1\x00"},          /* mov    $0x00,%r9b            */
	 {"\xeb\x1a"},              /* jmp    4000d2 <get_sc_addr>  */
	 {"\x58"},                  /* pop    %rax                  */
	 {"\x48\x31\xc9"},          /* xor    %rcx,%rcx             */
	 {"\x48\x31\xdb"},          /* xor    %rbx,%rbx             */
	 {"\x8a\x1c\x08"},          /* mov    (%rax,%rcx,1),%bl     */
	 {"\x4c\x39\xc3"},          /* cmp    %r8,%rbx              */
	 {"\x74\x10"},              /* je     4000d7 <exec_sc>      */
	 {"\x44\x30\xcb"},          /* xor    %r9b,%bl              */
	 {"\x88\x1c\x08"},          /* mov    %bl,(%rax,%rcx,1)     */
	 {"\x48\xff\xc1"},          /* inc    %rcx                  */
	 {"\xeb\xed"},              /* jmp    4000bf <xor_loop>     */
	 {"\xe8\xe1\xff\xff\xff"}}; /* callq  4000b8 <jmp_back>     */
 
 /*
 * 
 * Code taken from phiral.net
 *
 */
 
unsigned char decoder[] =
 "\x4d\x31\xc0"          /* xor    %r8,%r8               */
 "\x41\xb1\x00"          /* mov    $0x00,%r9b            */
 "\xeb\x1a"              /* jmp    4000d2 <get_sc_addr>  */
 "\x58"                  /* pop    %rax                  */
 "\x48\x31\xc9"          /* xor    %rcx,%rcx             */
 "\x48\x31\xdb"          /* xor    %rbx,%rbx             */
 "\x8a\x1c\x08"          /* mov    (%rax,%rcx,1),%bl     */
 "\x4c\x39\xc3"          /* cmp    %r8,%rbx              */
 "\x74\x10"              /* je     4000d7 <exec_sc>      */
 "\x44\x30\xcb"          /* xor    %r9b,%bl              */
 "\x88\x1c\x08"          /* mov    %bl,(%rax,%rcx,1)     */
 "\x48\xff\xc1"          /* inc    %rcx                  */
 "\xeb\xed"              /* jmp    4000bf <xor_loop>     */
 "\xe8\xe1\xff\xff\xff"; /* callq  4000b8 <jmp_back>     */


int main(int argc, char **argv) {
    char *file;
    struct stat sstat;
    int i, n, fd, len, xor_with;
    int decoder_len;
    unsigned char *fbuf, *ebuf;
    unsigned char bad_bytes[256] = {0};
    unsigned char good_bytes[256] = {0};
    int number_junk_instr, junk_len, junk_index, decoder_index_to_insert;
    int j, k;

    if (argc != 2) {
        fprintf(stderr, "Syntax: %s binary_file\n", argv[0]);
        exit(-1);
    }

    file = argv[1];
    /* open the sc.bin file and read all the bytes */
    if (lstat(file, &sstat) < 0) {
        fprintf (stderr, "File %s not found", file);
        exit(-1);
    }
    fprintf(stderr, "Perfect, processing file %s\n", file);

    len = sstat.st_size;
    if ((fbuf = (unsigned char *)malloc(len)) == NULL) {
        perror("malloc");
        exit(-1);
    }
    
    if ((fd = open(file, O_RDONLY)) < 0) {
        perror("open");
        _exit(-1);
    }

    if (read(fd, fbuf, len) != len) {
        perror("read");
        _exit(-1);
    }

    close(fd);

    /* try every byte xored, if its \x0 add to bad_bytes */
    for (n = 0; n < len; n++) {
        for (i = 1; i < 256; i++) {
             if ((i^*(fbuf+n)) == 0) bad_bytes[i] = i;
        }
    }  

    /* if its not a bad_byte its a good_one (ordered) */
    for (i = 1, n = 0; i < 256; i++) {
        if (bad_bytes[i] == '\0') good_bytes[n++] = i;
    }
    
    srand((unsigned)time(NULL));  
    //xor_with = good_bytes[rand()%n];
	xor_with = good_bytes[0];
    if (xor_with) {
        printf("\n[x] Choose to XOR with 0x%02x\n\n", xor_with);

        /* overwrite that 5th xor byte with the xor_with byte */
        decoder[5] = xor_with;
        decoder_matrix[1][2] = xor_with;
        
        /* Compute length of decoder */
        decoder_len = strlen((char *)decoder);
        printf("Decoder length is: %d\n", decoder_len);
        
        decoder_len = 0;
        for (k = 0; k < NUMBER_DECODER_INSTR; k++) {
        	decoder_len += strlen(decoder_matrix[k]);
        }
        printf("Decoder MATRIX length is: %d\n", decoder_len);
        
        /* Get a random junk instruction to write */
        number_junk_instr = 1;
        junk_index = rand()%NUMBER_JUNK_INSTR;
        /*printf("size of instruction in position 1:%d\n", sizeof(useless[2]));
        printf("strlen of instruction in position 1:%d\n", strlen(useless[2]));*/
        junk_len = strlen(useless[junk_index]);

		/* Get a random place to inject the junk instruction */
		decoder_index_to_insert = rand()%4;
		//TODO WE NEED TO RECOMPUTE THE OFFSETS OF THE BUFFER IN ORDER TO INJECT THE CODE...
		printf("Inserting the junk instruction in: %d\n", decoder_index_to_insert);
		
        if ((ebuf = (unsigned char *)malloc(decoder_len+len+1+junk_len)) == NULL) {
            perror("malloc");
            _exit(-1);
        }
        memset(ebuf, '\x0', sizeof(ebuf));

        for (i = 0, j = 0; i < NUMBER_DECODER_INSTR; i++) {
        	if (i == decoder_index_to_insert) {
        		for (int x = 0; x < junk_len; x++, j++) {
        			ebuf[(j)] = useless[junk_index][x];
				}
        	}
        	for (k = 0; k < strlen(decoder_matrix[i]); k++,j++) {
           		ebuf[(j)] = decoder_matrix[i][k];
            }
            //ebuf[(j)] = decoder[i];
        }
        printf("Bytes copied to buffer are: %d\n", j);
        printf("Size of the buffer after decoder: %d\n", strlen((char *) ebuf));
        /* copy the xored shellcode bytes in */
        for (i = 0; i < len; i++) {
            ebuf[(i+decoder_len+junk_len)] = xor_with^*(fbuf+i);
        }
		printf("Size of the buffer after encoded: %d\n", strlen((char *) ebuf));
		
        printf("char code[]=\"");
        for (i = 0; i < strlen((char *)ebuf); i++) {
            /*if (i > 0 && i % 15 == 0)
                printf("\"\n\""); */
            printf("\\x%02x", ebuf[i]);
        }
        printf("\";\n\n");

        return 0;
    } else {
        printf("\n[*] No byte found to XOR with :(\n");
        _exit(-1);
    }

    return 0;
}

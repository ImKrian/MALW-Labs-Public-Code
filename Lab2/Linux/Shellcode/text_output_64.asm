;text_output.asm
[SECTION .text]

global _start
_start:
	jmp short ender
	starter:
	
	xor eax, eax ; clean up the registers
	xor ebx, ebx ; as we shall see later, using these instructions
	xor edx, edx ; allow us to avoid having nulls (\0) on our
	xor ecx, ecx ; shellcode
	
	mov al, 64; search which is the code for write system call
	mov bl, 1 ; stdout file descriptor
	pop ecx ; get the address of the string from the stack
	
	; (IP from call!!)
	mov dl, 16 ; length of the string on the last line, consider \0!
	int 0x80 ; Interrupt for kernel to run the syscall
	
	xor eax, eax
	mov al, 1 ; exit the application
	xor ebx, ebx
	int 0x80
	
	ender:
	call starter ; put the address of the string on the stack
	db 'PUT SOME STRING'
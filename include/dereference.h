#ifndef dereference_h
#define dereference_h

#include <sys/ptrace.h>
#include <stdlib.h>

/* Includes functions used for dereferencing virtual pointers into other types of data */

char* deref_asciistring(pid_t pid, void* ptr); 			// PyASCIIObject* -> char*
void* deref_vptr(pid_t pid, void* ptr); 				// void* -> void*

#endif

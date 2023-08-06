#include <sys/ptrace.h>
#include <stdlib.h>

#include "dereference.h"
#include "memory.h"
#include "offsets.h"

char* deref_asciistring(pid_t pid, void* ptr) {
	/* Python ASCII strings are stored in PyASCIIObject
	 * The string data follows the PyASCIIObject struct, and important information like length
	 * and state are located within the struct. The pointer to the struct can be assumed to be
	 * the pointer to the PyUnicodeObject as long as we know that the string is ASCII 
	 *
	 * During allocation, the struct is allocated on the heap which is immediately followed the 
	 * string data *
	 */

	size_t length = (size_t)mem_peek(pid, ptr+OFF_T_PYASCII_LENGTH); /* Length stored as size_t */

	/* Read the entire string using file and copy it over to heap buffer */
	char* string = (char*)malloc(length+1);
	string[length] = '\0';

	int read = mem_readchunk(pid, ptr+OFF_T_PYASCII_DATA, string, length);
	if (read == -1) {
		free(string);
		return NULL;
	}

	return string;
}

void* deref_vptr(pid_t pid, void* ptr) {
	/* Dereferences a virtual pointer to give another virtual pointer */
	return (void*)ptrace(PTRACE_PEEKDATA, pid, ptr, NULL);
}

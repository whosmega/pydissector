#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "memory.h"

/* Opening/Closing file descriptors for custom usage */

FILE* mem_open(pid_t pid) {
	char path[100];
	sprintf(path, "/proc/%d/mem", pid);

	FILE* mem = fopen(path, "r");
	return mem;
}

void mem_close(FILE* mem) {
	fclose(mem);
}


/* Peeking Through PTRACE */

long mem_peek(pid_t pid, void* ptr) {
	/* Process has to be attached beforehand */
	long data = ptrace(PTRACE_PEEKDATA, pid, ptr);
	return data;
}

/* Reading large chunks of memory using file descriptors */

int mem_readchunk(pid_t pid, void* ptr, void* buffer, size_t size) {
	FILE* mem = mem_open(pid);
	if (mem == NULL) return -1;

	/* Reads a chunk from virtual pointer into a buffer */
	fseek(mem, (long)ptr, SEEK_SET);
	int read = fread(buffer, size, 1, mem);
	mem_close(mem);

	if (read != 1) {
		return -1;
	}

	return 0;
}

/* Scanning for a bytearray in memory */

void* mem_scan(pid_t pid, void* base, void* end, uint8_t* byteArray, size_t length) {
	/* Scans virtual memory for byte array between base and end, returns the first match */

	/* 16 MiB allocation page buffer */
#define PAGE_SIZE 16777216 										/* 16 MiB */
	uint8_t* pageBuffer = (uint8_t*)malloc(PAGE_SIZE);
	unsigned matchIndex = 0;

	/* We are using /proc/{pid}/mem which lets us access the virtual memory in big blocks,
	 * seek to the base pointer of search address as we start reading from here */
	FILE* mem = mem_open(pid);
	if (mem == NULL) return NULL;

	fseek(mem, (long)base, SEEK_SET);

	unsigned currentPage = 0;
	size_t currentPageLength = 0;

	for (;;) {
		/* 16 MiB blocks of data are read into the buffer, the bytearray scan is done across it
		 * and at the end of the page, currentPage is incremented
		 * matchIndex is preserved across pages so this also means that the bytearray can be 
		 * in the middle of 2 pages. */
		currentPageLength = fread(pageBuffer, 1, PAGE_SIZE, mem);

		for (unsigned i = 0; i < currentPageLength; i++) {
			/* Scan Page */
			if (pageBuffer[i] == byteArray[matchIndex]) {
				matchIndex++;
				if (matchIndex == length) {
					/* Found Byte Array */
					free(pageBuffer);
					mem_close(mem);
					return (void*)((base + currentPage*PAGE_SIZE + i) - (length - 1));
				}
			} else matchIndex = 0;
		}

		if (currentPageLength != PAGE_SIZE) {
			/* Last page evaluated */
			break;
		}
		currentPage++;
	}

	/* Byte array not found */
	free(pageBuffer);
	mem_close(mem);
	return NULL;

#undef PAGE_SIZE
}

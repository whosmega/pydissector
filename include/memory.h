#ifndef memory_h
#define memory_h

#include <unistd.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdint.h>

FILE* mem_open(pid_t pid);
void mem_close(FILE* mem);

long mem_peek(pid_t pid, void* ptr);
int mem_readchunk(pid_t pid, void* ptr, void* buffer, size_t size);
void* mem_scan(pid_t pid, void* base, void* end, uint8_t* byteArray, size_t length);

#endif

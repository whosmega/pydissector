/* Designed to work with and tested with 3.13.0 alpha 0. Can't guarantee any other version.
 * Program should always execute with elevated permissions in order to access proc directories
   and modify .data section of the cpython binary. */

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "memory.h"
#include "dereference.h"
#include "offsets.h"

void* findPyRuntime(char* chpid, pid_t pid) {
  char path[100];
  char pidpath[100];
  FILE* file = NULL;

  printf("Scanning for _PyRuntime in the process virtual memory\n");
  /* Read symlink at /proc/{pid}/exe to find the path of the process ID
   * so we can use it as reference to look for exe regions in the map */
  sprintf((char*)&path, "/proc/%s/exe", chpid);
  size_t charsRead = readlink((char*)&path, pidpath, 99);
  if (charsRead == -1) return NULL; 								// Read error
  pidpath[charsRead] = '\0'; 										// NULL terminate the string

  /* Now proceed to read map */
  sprintf((char*)&path, "/proc/%s/maps", chpid);
  file = fopen(path, "r"); 

  for (;;) {
	/* p1, p2 and p3 are 3 16 bit parts which are assembled to form a 48 bit pointer
	 * note: Pointers are only limited to 48 bit because of the current fscanf usage.
	 * This is a makeshift scanner using fscanf but will probably be upgraded to a proper 
	 * file parser later on
	 *
	 * Identifier contains the information about who owns the region in the virtual memory
	 * This is usually the filepath of the process itself for the executable region which 
	 * also contains the .data section allocation for global variables 
	 *
	 * Perms contains the perms of the region (read/write/execute/private) */
	uint32_t p1, p2, p3;
  	char identifier[100];
  	char perms[5];
  	int eof = 0;

    eof = fscanf(file, "%4x%4x%4x", &p1, &p2, &p3);
	if (eof == EOF) return NULL;

    if (p1 == 0xFFFF) {
      /* VSYSCALL table reached, this is the end of scanning */
      break;
    }
    void* min = (void*)(((uint64_t)p1 << 32) | (p2 << 16) | p3);

    eof = fscanf(file, "-%4x%4x%4x", &p1, &p2, &p3);
	if (eof == EOF) goto end;

    void* max = (void*)(((uint64_t)p1 << 32) | (p2 << 16) | p3);

	char c;
    eof = fscanf(file, "%s %*s %*s %*s%c", perms, &c);
	if (eof == EOF) goto end;

	c = fgetc(file);
	if (c == EOF) goto end;
	else if (c != '\n') {
		/* Identifier avaiable */
		fseek(file, -1, SEEK_CUR); 				/* Unread the character */
		eof = fscanf(file, "%s", identifier);
		if (eof == EOF) goto end;
	} else {
		/* Idenifier not available, but not a valid error or EOF */
		strcpy(identifier, "[Unknown]");
	}

	if (perms[1] == 'w' && strcmp(identifier, pidpath) == 0) {
		/* Found a writable region owned by executable,
		 * most likely to be the global allocation region.
		 * Look for PyRuntime here by trying to scan cookie 'xdebugpy' which is
		 * the top of the debugging header at the top of the struct */

		printf("Found possible match: [%p-%p]\n", min, max);
		printf("Scanning for cookie 'xdebugpy'\n");
	
		uint8_t cookie[8] = {0x78, 0x64, 0x65, 0x62, 0x75, 0x67, 0x70, 0x79};
		void* PyRuntime = mem_scan(pid, min, max-1, (uint8_t*)&cookie, 8);

		if (PyRuntime == NULL) {
			printf("Could not find _PyRuntime, continuing\n");
		} else {
			printf("_PyRuntime successfully located at address %p\n", PyRuntime);
			return PyRuntime;
		}
	} else {
		/* Doesnt match, we skip this region */
		printf("Skipping region [%p-%p]\n", min, max);
	}
  }

end:
  printf("Error: Could not find a suitable global data allocation\n");
  fclose(file);
  return NULL;
}

void printPyInterpreterFrame(pid_t pid, void* ptr, _Py_DebugOffsets offsets) {
	/* Prints information about the _PyInterpreterFrame given in virtual pointer ptr */
	void* PyCodeObject = deref_vptr(pid, ptr + offsets.interpreter_frame.executable);
	char* functionName = deref_asciistring(pid, deref_vptr(pid, PyCodeObject + offsets.code_object.name));

	printf("== Call Frame Info ==\n");
	printf("Function Name: %s\n", functionName);
	printf("=====================\n");

	free(functionName);
}

int start(char* pid) {
  /* Attach to process */
  pid_t intpid = (pid_t)strtol((const char*)pid, NULL, 10);
  int status = ptrace(PTRACE_ATTACH, intpid, NULL, NULL);

  if (status == -1) {
	  printf("Error: Could not attach to process %d, %s\n", (int)intpid, strerror(errno));
	  return 3;
  }

  waitpid(intpid, NULL, 0);
  printf("Successfully attached to process %d\n", (int)intpid);

  /* Scanning and Injection */

  void* PyRuntime = findPyRuntime(pid, intpid);
  if (PyRuntime == NULL) {
	  ptrace(PTRACE_DETACH, intpid, NULL, NULL);
	  return 3;
  }

  /* Read debug offsets struct from memory into offsets */
  _Py_DebugOffsets offsets;
  int ret = mem_readchunk(intpid, PyRuntime, &offsets, sizeof(_Py_DebugOffsets));
  if (ret == -1) {
	  ptrace(PTRACE_DETACH, intpid, NULL, NULL);
	  return 4;
  }

  printf("\nVersion: %x%x\n", (uint32_t)(offsets.version>>32), (uint32_t)(offsets.version&0xFFFFFFFF));
  printf("Detecting Pointers for Structs...\n");

  /* Get Pointers using offsets */
  void* interpState  = deref_vptr(intpid, PyRuntime + offsets.runtime_state.interpreters_head);
  void* threadState  = deref_vptr(intpid, interpState + offsets.interpreter_state.threads_head);
  void* cframe       = deref_vptr(intpid, threadState + offsets.thread_state.cframe);
  void* frame 		 = deref_vptr(intpid, cframe + offsets.cframe.current_frame);

  printf("PyInterpreterState -> %p [Offset: %ld]\n", interpState, offsets.runtime_state.interpreters_head);
  printf("PyThreadState -> %p [Offset: %ld]\n", threadState, offsets.interpreter_state.threads_head);
  printf("CurrentFrame -> %p [Offset: %ld]\n", cframe, offsets.thread_state.cframe);
  printf("_PyInterpreterFrame -> %p [Offset: %ld]\n", frame, offsets.cframe.current_frame); 

  printf("\n\n");
  printPyInterpreterFrame(intpid, frame, offsets);
  
  /* Detach from process */
  ptrace(PTRACE_DETACH, intpid, NULL, NULL);
  return 0;
}

int main(int argc, char** argv) {
  /* Check root privileges */
  if (getuid() && geteuid()) {
    printf("Error: You need to start this program with root privileges\n");
    return 1;
  }

  if (argc < 2) {
    printf("Error: Please specify the PID of the python process\n");
    return 2;
  }

  int ret = start(argv[1]);
  return ret;
}

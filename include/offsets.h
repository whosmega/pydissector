#ifndef debugoffsets_h
#define debugoffsets_h

#include <sys/types.h>
#include <stdint.h>


/* As defined in 3.13.0 alpha 0 
 * https://github.com/python/cpython/blob/main/Include/internal/pycore_runtime.h */

typedef enum {
	/* PyASCIIObject */
	OFF_T_PYASCII_DATA 		= 	40,
	OFF_T_PYASCII_LENGTH 	= 	16
} ManualOffset;

typedef struct _Py_DebugOffsets {
    char cookie[8];
    uint64_t version;
    // Runtime state offset;
    struct _runtime_state {
        off_t finalizing;
        off_t interpreters_head;
    } runtime_state;

    // Interpreter state offset;
    struct _interpreter_state {
        off_t next;
        off_t threads_head;
        off_t gc;
        off_t imports_modules;
        off_t sysdict;
        off_t builtins;
        off_t ceval_gil;
        off_t gil_runtime_state_locked;
        off_t gil_runtime_state_holder;
    } interpreter_state;

    // Thread state offset;
    struct _thread_state{
        off_t prev;
        off_t next;
        off_t interp;
        off_t cframe;
        off_t thread_id;
        off_t native_thread_id;
    } thread_state;

    // InterpreterFrame offset;
    struct _interpreter_frame {
        off_t previous;
        off_t executable;
        off_t prev_instr;
        off_t localsplus;
        off_t owner;
    } interpreter_frame;

    // CFrame offset;
    struct _cframe {
        off_t current_frame;
        off_t previous;
    } cframe;

    // Code object offset;
    struct _code_object {
        off_t filename;
        off_t name;
        off_t linetable;
        off_t firstlineno;
        off_t argcount;
        off_t localsplusnames;
        off_t localspluskinds;
        off_t co_code_adaptive;
    } code_object;

    // PyObject offset;
    struct _pyobject {
        off_t ob_type;
    } pyobject;

    // PyTypeObject object offset;
    struct _type_object {
        off_t tp_name;
    } type_object;

    // PyTuple object offset;
    struct _tuple_object {
        off_t ob_item;
    } tuple_object;

	struct _manual {
		off_t pyascii_length;
	} manual;
} _Py_DebugOffsets;

#endif

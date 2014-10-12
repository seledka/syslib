#ifndef MEM_H_INCLUDED
#define MEM_H_INCLUDED

#include <windows.h>

#include "syslib\mem.h"

#ifdef __cplusplus
extern "C"
#endif
unsigned long xor128(int val);

#define free(x) MemFree(x)
#define malloc(x) MemAlloc(x)
#define calloc(x,y) malloc(x*y)

#define rand() xor128(RAND_MAX)

#endif // MEM_H_INCLUDED

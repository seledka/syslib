#ifndef MEM_H_INCLUDED
#define MEM_H_INCLUDED

#define BLOCK_ALLOCED 0xABBABABA
#define BLOCK_FREED   0xDEADBEEF

#define HEAP_LFH 2

#define RALIGN(dwToAlign, dwAlignOn) (((dwToAlign)+(dwAlignOn)-1)&(~((dwAlignOn)-1)))

#define MEM_SAFE_BYTES 2

#endif // MEM_H_INCLUDED

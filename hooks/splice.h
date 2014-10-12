#ifndef SPLICE_H_INCLUDED
#define SPLICE_H_INCLUDED

#include <windows.h>
#include "stdint.h"

#ifdef _AMD64_
#include "hde64\hde64.h"
#define hdes hde64s
#else
#include "hde32\hde32.h"
#define hdes hde32s
#endif

#define KB_SIZE		1024
#define MB_SIZE		(1024 * KB_SIZE)
#define GB_SIZE		(1024 * MB_SIZE)

#ifdef _X86_
#define SizeOfCode(x) hde32_disasm(x,&hs)
#else
#define SizeOfCode(x) hde64_disasm(x,&hs)
#endif

#include <pshpack1.h>
typedef struct
{
    byte  opcode;
    DWORD operand;
} JMP_REL,CALL_REL;

struct MOV_RAX
{
    WORD opcode;
    DWORD_PTR operand;
};

struct JMP_RAX
{
    WORD opcode;
};

typedef struct
{
    WORD  opcode;
    DWORD operand;
} JMP_ABS,CALL_ABS,JCC_REL;

struct JCC_ABS
{
    byte  opcode;
    byte  dummy0;
    byte  dummy1;
    byte  dummy2;
    WORD  dummy3;
    DWORD operand;
};
#include <poppack.h>

struct TEMP_ADDR
{
    LPVOID lpAddress;
    SIZE_T dwPosition;
    SIZE_T dwPc;
};


#define JUMP_SIZE sizeof(JMP_REL)
#define RAX_JUMP_SIZE sizeof(MOV_RAX)+sizeof(JMP_RAX)

#ifdef _AMD64_
#define SPLICE_BACKUP_SIZE RAX_JUMP_SIZE*5
#else
#define SPLICE_BACKUP_SIZE JUMP_SIZE*5
#endif

#define MAX_JUMPS 20

#define LODWORD(l) ((DWORD)((DWORDLONG)(l)))
#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFFF))
#define MAKEDWORDLONG(a,b) ((DWORDLONG)(((DWORD)(a))|(((DWORDLONG)((DWORD)(b)))<<32)))

#include "hook_api.h"
namespace SYSLIB
{
    PHOOK_INFO Splice_PrepareAndPathFunc(LPVOID lpFunc,LPVOID lpHandler,DWORD dwFlags);
    bool Splice_PathFunc(PHOOK_INFO lpHook);
    bool Splice_UnpathFunc(PHOOK_INFO lpHook);
    void FreeReleayPlace(LPVOID lpFunc,DWORD dwSize);
};

#include <pshpack1.h>
#ifndef _X86_
struct HOOK_STUB
{
    byte bDbg;

    byte bDummy0;        ///    pop rax              0x58
    byte bDummy1;        ///    push rcx             0x51
    byte bDummy2;        ///    push rdx             0x52
    WORD wDummy1;        ///    push r8              0x5041
    WORD wDummy2;        ///    push r9              0x5141

    byte bDummy3[3];     ///    mov rdx,rax          0x48,0x89,0xC2
    struct
    {
        WORD wDummy;     ///    mov rcx,???          0xB948
        LPVOID lpAPI;
    } s1;
    struct
    {
        WORD wDummy;     ///    mov rax,???          0xB848
        LPVOID lpGetHandlerAddress;
    } s2;
    byte bDummy4[4];     ///    sub rsp,0x20         0x48,0x83,0xEC,0x20
    WORD wDummy5;        ///    call rax             0xD0FF
    byte bDummy5[4];     ///    add rsp,0x20         0x48,0x83,0xC4,0x20

    WORD wDummy6;        ///    pop r9               0x5841
    WORD wDummy7;        ///    pop r8               0x5941
    byte bDummy7;        ///    pop rdx              0x5A
    byte bDummy8;        ///    pop rcx              0x59

    WORD wDummy8;        ///    call rax             0xD0FF

    byte bDummy11;       ///    push rax             0x50
    byte bDummy12;       ///    push rax             0x50
    struct
    {
        WORD wDummy;     ///    mov rcx,???          0xB948
        LPVOID lpAPI;
    } s3;
    struct
    {
        WORD wDummy;     ///    mov rax,???          0xB848
        LPVOID lpEnableHookForCallingThread;
    } s4;
    byte bDummy13[4];    ///    sub rsp,0x20         0x48,0x83,0xEC,0x20
    WORD wDummy11;       ///    call rax             0xD0FF
    byte bDummy14[4];    ///    add rsp,0x20         0x48,0x83,0xC4,0x20
    byte bDummy15[5];    ///    mov [rsp+1*8],rax    0x48,0x89,0x44,0x24,0x08
    byte bDummy16;       ///    pop rax              0x58

    byte bDummy17;       ///    retn                 0xC3
};
#else
struct HOOK_STUB
{
    byte bDbg;

    byte bDummy2;        ///    pusha                0x60
    byte bDummy5[4];     ///    mov edx,[esp+8*4]    0x8B,0x54,0x24,0x20
    struct
    {
        byte bDummy;     ///    mov ecx,???          0xB9
        LPVOID lpAPI;
    } s1;
    struct
    {
        byte bDummy;     ///    mov eax,???          0xB8
        LPVOID lpGetHandlerAddress;
    } s2;
    WORD wDummy1;        ///    call eax             0xD0FF
    byte bDummy6[4];     ///    mov [esp+8*4],eax    0x89,0x44,0x24,0x20
    byte bDummy7;        ///    popa                 0x61

    byte bDummy8;        ///    pop eax              0x58
    WORD wDummy2;        ///    call eax             0xD0FF

    byte bDummy9;        ///    push eax             0x50
    byte bDummy10;       ///    pusha                0x60
    struct
    {
        byte bDummy;     ///    mov ecx,???          0xB9
        LPVOID lpAPI;
    } s3;
    struct
    {
        byte bDummy;     ///    mov eax,???          0xB8
        LPVOID lpEnableHookForCallingThread;
    } s4;
    WORD wDummy3;        ///    call eax             0xD0FF
    byte bDummy12[4];    ///    mov [esp+8*4],eax    0x89,0x44,0x24,0x20
    byte bDummy13;       ///    popa                 0x61

    byte bDummy14;       ///    retn                 0xC3
};
#endif
#include <poppack.h>

/// #define DEBUG_OPCODE 0xCC
///
 #define DEBUG_OPCODE 0x90

#endif // SPLICE_H_INCLUDED

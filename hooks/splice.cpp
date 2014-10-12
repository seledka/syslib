#include "sys_includes.h"
#include <stddef.h>

#include "splice.h"

#include "syslib\debug.h"
#include "syslib\mem.h"

namespace SYSLIB
{
    LPVOID GetRelativeBranchDestination(LPVOID lpInst,hdes *hs)
    {
    #ifdef _AMD64_
        return (LPVOID)MAKEDWORDLONG((LODWORD(lpInst)+hs->len+hs->imm.imm32),HIDWORD(lpInst));
    #else
        return (LPVOID)((DWORD)lpInst+hs->len+hs->imm.imm32);
    #endif
    }

    inline bool IsInternalJump(LPVOID lpTarget,ULONG_PTR dest)
    {
        ULONG_PTR pt=(ULONG_PTR)lpTarget;
        return ((pt <= dest) && (dest <= pt+JUMP_SIZE));
    }

    static void AppendTempAddress(LPVOID lpAddress,SIZE_T dwPos,CALL_ABS *lpInst,TEMP_ADDR *lpAddr,LPVOID *lpAddrTable)
    {
    #ifdef _AMD64_
        *lpAddrTable=lpAddress;
    #else
        lpAddr->lpAddress=lpAddress;
    #endif
        lpAddr->dwPosition=dwPos+((ULONG_PTR)&lpInst->operand-(ULONG_PTR)lpInst);
        lpAddr->dwPc=dwPos+sizeof(*lpInst);
        return;
    }

    static void AppendTempAddress(LPVOID lpAddress,SIZE_T dwPos,JCC_ABS *lpInst,TEMP_ADDR *lpAddr,LPVOID *lpAddrTable)
    {
    #ifdef _AMD64_
        *lpAddrTable=lpAddress;
    #else
        lpAddr->lpAddress=lpAddress;
    #endif
        lpAddr->dwPosition=dwPos+((ULONG_PTR)&lpInst->operand-(ULONG_PTR)lpInst);
        lpAddr->dwPc=dwPos+sizeof(*lpInst);
        return;
    }

    static void AppendTempAddress(LPVOID lpAddress,SIZE_T dwPos,CALL_REL *lpInst,TEMP_ADDR *lpAddr,LPVOID *lpAddrTable)
    {
    #ifdef _AMD64_
        *lpAddrTable=lpAddress;
    #else
        lpAddr->lpAddress=lpAddress;
    #endif
        lpAddr->dwPosition=dwPos+((ULONG_PTR)&lpInst->operand-(ULONG_PTR)lpInst);
        lpAddr->dwPc=dwPos+sizeof(*lpInst);
        return;
    }

    #ifdef _AMD64_
    static void AppendRipRelativeAddress(LPVOID lpInst,SIZE_T dwPos,hdes *hs,TEMP_ADDR *lpAddr)
    {
        lpAddr->lpAddress=(LPVOID)((ULONG_PTR)lpInst+hs->len+hs->disp.disp32);
        lpAddr->dwPosition=dwPos+hs->len-((hs->flags & 0x3C) >> 2)-4;
        lpAddr->dwPc=dwPos+hs->len;
        return;
    }

    static bool WriteAbsoluteJump(LPVOID lpFrom,LPVOID lpTo)
    {
        bool bRet=false;
        DWORD dwOldProtect;
        VirtualProtect(lpFrom,RAX_JUMP_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);
        if (SYSLIB_SAFE::CheckParamWrite(lpFrom,RAX_JUMP_SIZE))
        {
            MOV_RAX mov;
            mov.opcode=0xb848;
            mov.operand=(DWORD_PTR)lpTo;
            memcpy(lpFrom,&mov,sizeof(mov));

            JMP_RAX jmp;
            jmp.opcode=0xe0ff;
            memcpy((byte*)lpFrom+sizeof(mov),&jmp,sizeof(jmp));

            VirtualProtect(lpFrom,RAX_JUMP_SIZE,dwOldProtect,&dwOldProtect);

            bRet=true;
        }
        return bRet;
    }

    // TODO (Гость#1#): сделать поиск через хидер (читать размер)
    static LPVOID GetPlaceForRelay(LPVOID lpFunc,DWORD dwSize)
    {
        DWORD dwOffset=0;
        LPVOID lpRelay=NULL;
        while (true)
        {
            MEMORY_BASIC_INFORMATION mi={0};
            if (VirtualQuery((LPBYTE)lpFunc+dwOffset,&mi,sizeof(mi)))
            {
                DWORD dwFreeSize=0;
                LPBYTE lpRegionEnd=(LPBYTE)mi.BaseAddress+mi.RegionSize;
                if (mi.State == MEM_COMMIT)
                {
                    while ((ULONG_PTR)lpRegionEnd > (ULONG_PTR)mi.BaseAddress)
                    {
                        if (*(lpRegionEnd-1))
                            break;

                        dwFreeSize++;
                        lpRegionEnd--;
                    }
                }
                else if (mi.State == MEM_FREE)
                {
                    LPBYTE lpNewRegion=(LPBYTE)VirtualAlloc(mi.BaseAddress,dwSize,MEM_COMMIT,PAGE_READWRITE);
                    if (lpNewRegion)
                    {
                        lpRegionEnd=lpNewRegion;
                        dwFreeSize=dwSize;
                    }
                }

                if ((dwFreeSize >= dwSize) && ((ULONG_PTR)lpRegionEnd-(ULONG_PTR)lpFunc <= 2*GB_SIZE))
                {
                    lpRelay=lpRegionEnd;

                    /// помечаем память как используемую
                    DWORD dwOldProtect=0;
                    VirtualProtect(lpRelay,dwSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
                    memset(lpRelay,0x90,dwSize);
                    VirtualProtect(lpRelay,dwSize,dwOldProtect,&dwOldProtect);
                    FlushInstructionCache(GetCurrentProcess(),NULL,0);
                    break;
                }

                dwOffset=((LPBYTE)mi.BaseAddress+mi.RegionSize)-(LPBYTE)lpFunc;
                if (dwOffset > 2*GB_SIZE)
                    break;

                dwOffset+=2;
            }
        }
        return lpRelay;
    }

    void FreeReleayPlace(LPVOID lpRelay,DWORD dwSize)
    {
        if (lpRelay)
        {
            DWORD dwOldProtect=0;
            VirtualProtect(lpRelay,dwSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
            memset(lpRelay,0,dwSize);
            VirtualProtect(lpRelay,dwSize,dwOldProtect,&dwOldProtect);
            FlushInstructionCache(GetCurrentProcess(),NULL,0);
        }
        return;
    }
    #endif

    inline void SetJccOpcode(hdes *hs,JCC_REL *lpInst)
    {
        UINT n=(((hs->opcode != 0x0F) ? hs->opcode:hs->opcode2) & 0x0F);
        lpInst->opcode=0x800F|(n<<8);
        return;
    }

    inline void SetJccOpcode(hdes *hs,JCC_ABS *lpInst)
    {
        UINT n=(((hs->opcode != 0x0F) ? hs->opcode:hs->opcode2) & 0x0F);
        lpInst->opcode=0x70|n;
        return;
    }

    #ifdef _AMD64_
    static LPVOID CreateBridge(LPVOID lpFunc,LPVOID lpBackup,SIZE_T *dwBackupCodeSize,ULONG_PTR *lpTable)
    #else
    static LPVOID CreateBridge(LPVOID lpFunc,LPVOID lpBackup,SIZE_T *dwBackupCodeSize)
    #endif
    {
        #ifdef _AMD64_
        LPVOID lpBridge=GetPlaceForRelay(lpFunc,JUMP_SIZE*6);
        #else
        LPVOID lpBridge=MemQuickAlloc(JUMP_SIZE*6);
        #endif
        if (lpBridge)
        {
            DWORD dwOldProtect=0;
            VirtualProtect(lpBridge,JUMP_SIZE*6,PAGE_EXECUTE_READWRITE,&dwOldProtect);

    #ifdef _AMD64_
            CALL_ABS call={0x15FF,0x00000000};
            JMP_ABS jmp={0x25FF,0x00000000};
            JCC_ABS jcc={0x70,0x02,0xEB,0x06,0x25FF,0x00000000};
            int dwTmpAddrsCount=0;
    #else
            CALL_REL call={0xE8,0x00000000};
            JMP_REL jmp={0xE9,0x00000000};
            JCC_REL jcc={0x800F,0x00000000};
    #endif
            TEMP_ADDR TmpAddr[MAX_JUMPS]={0};
            int dwTmpAddrCount=0;

            SIZE_T dwOldPos=0,dwNewPos=0;
            ULONG_PTR dwJmpDest=0;
            bool bDone=false;
            while (!bDone)
            {
                hdes hs;
                LPVOID lpInst=(LPVOID)((ULONG_PTR)lpFunc+dwOldPos);
                SIZE_T dwCopySize=SizeOfCode(lpInst);
                if ((hs.flags & F_ERROR) == F_ERROR)
                    break;

                LPVOID lpCopySrc=lpInst;
                if ((ULONG_PTR)lpInst-(ULONG_PTR)lpFunc >= JUMP_SIZE)
                {
                    LPVOID lpTmpAddr=0;
    #ifdef _AMD64_
                    lpTmpAddr=&lpTable[dwTmpAddrsCount++];
                    if (dwTmpAddrsCount > MAX_JUMPS)
                        break;
    #endif
                    AppendTempAddress(lpInst,dwNewPos,&jmp,&TmpAddr[dwTmpAddrCount++],(void **)lpTmpAddr);
                    if (dwTmpAddrCount > MAX_JUMPS)
                        break;

                    lpCopySrc=&jmp;
                    dwCopySize=sizeof(jmp);

                    bDone=true;
                }
    #ifdef _AMD64_
                else if ((hs.modrm & 0xC7) == 0x05) // RIP-based
                {
                    AppendRipRelativeAddress(lpInst,dwNewPos,&hs,&TmpAddr[dwTmpAddrCount++]);
                    if (dwTmpAddrCount > MAX_JUMPS)
                        break;

                    if ((hs.opcode == 0xFF) && (hs.modrm_reg == 4)) // jmp
                        bDone=true;
                }
    #endif
                else if (hs.opcode == 0xE8) // call
                {
                    LPVOID lpTmpAddr=0;
    #ifdef _AMD64_
                    lpTmpAddr=&lpTable[dwTmpAddrsCount++];
                    if (dwTmpAddrsCount > MAX_JUMPS)
                        break;
    #endif
                    AppendTempAddress(GetRelativeBranchDestination(lpInst,&hs),dwNewPos,&call,&TmpAddr[dwTmpAddrCount++],(void **)lpTmpAddr);
                    if (dwTmpAddrCount > MAX_JUMPS)
                        break;

                    lpCopySrc=&call;
                    dwCopySize=sizeof(call);
                }
                else if ((hs.opcode & 0xFD) == 0xE9) // jmp
                {
                    LPVOID lpDest=GetRelativeBranchDestination(lpInst,&hs);

                    if (IsInternalJump(lpFunc,(ULONG_PTR)lpDest))
                        dwJmpDest=max(dwJmpDest,(ULONG_PTR)lpDest);
                    else
                    {
                        LPVOID lpTmpAddr=0;
    #ifdef _AMD64_
                        lpTmpAddr=&lpTable[dwTmpAddrsCount++];
                        if (dwTmpAddrsCount > MAX_JUMPS)
                            break;
    #endif
                        AppendTempAddress(lpDest,dwNewPos,&jmp,&TmpAddr[dwTmpAddrCount++],(void **)lpTmpAddr);
                        if (dwTmpAddrCount > MAX_JUMPS)
                            break;

                        lpCopySrc = &jmp;
                        dwCopySize = sizeof(jmp);

                        bDone=((ULONG_PTR)lpInst >= dwJmpDest);
                    }
                }
                else if (((hs.opcode & 0xF0) == 0x70) || (hs.opcode == 0xE3) || ((hs.opcode2 & 0xF0) == 0x80)) // jcc
                {
                    LPVOID lpDest=GetRelativeBranchDestination(lpInst,&hs);

                    if (IsInternalJump(lpFunc,(ULONG_PTR)lpDest))
                        dwJmpDest=max(dwJmpDest,(ULONG_PTR)lpDest);
                    else if (hs.opcode == 0xE3) // jcxz, jecxz
                    {
                        bDone=false;
                        break;
                    }
                    else
                    {
                        LPVOID lpTmpAddr=0;
    #ifdef _AMD64_
                        lpTmpAddr=&lpTable[dwTmpAddrsCount++];
                        if (dwTmpAddrsCount > MAX_JUMPS)
                            break;
    #endif
                        AppendTempAddress(lpDest,dwNewPos,&jcc,&TmpAddr[dwTmpAddrCount++],(void **)lpTmpAddr);
                        if (dwTmpAddrCount > MAX_JUMPS)
                            break;

                        SetJccOpcode(&hs,&jcc);
                        lpCopySrc=&jcc;
                        dwCopySize=sizeof(jcc);
                    }
                }
                else if (((hs.opcode & 0xFE) == 0xC2) || // ret
                         ((hs.opcode & 0xFD) == 0xE9) || // jmp rel
                         (((hs.modrm & 0xC7) == 0x05) && ((hs.opcode == 0xFF) && (hs.modrm_reg == 4))) || // jmp rip
                         ((hs.opcode == 0xFF) && (hs.opcode2 == 0x25))) // jmp abs
                    bDone=((ULONG_PTR)lpInst >= dwJmpDest);

                if (((ULONG_PTR)lpInst < dwJmpDest) && (dwCopySize != hs.len))
                {
                    bDone=false;
                    break;
                }

                memcpy((byte*)lpBridge+dwNewPos,lpCopySrc,dwCopySize);

                dwOldPos+=hs.len;
                dwNewPos+=dwCopySize;
            }

            if (bDone)
            {
                memcpy(lpBackup,lpFunc,dwOldPos);
                *dwBackupCodeSize=dwOldPos;
    #ifdef _AMD64_
                int dwAddrTblPos=0;
    #endif
                byte *lpTrampoline=(byte*)lpBridge;
                for (int i=0; i < dwTmpAddrCount; i++)
                {
                    LPVOID lpAddr;
    #ifdef _AMD64_
                    if ((ULONG_PTR)TmpAddr[i].lpAddress < 0x10000)
                        lpAddr=&lpTable[dwAddrTblPos++];
                    else
    #endif
                        lpAddr=TmpAddr[i].lpAddress;

                    *(DWORD*)(lpTrampoline+TmpAddr[i].dwPosition)=(ULONG_PTR)lpAddr-((ULONG_PTR)lpBridge+TmpAddr[i].dwPc);
                    lpTrampoline+=TmpAddr[i].dwPc;
                }
            }
            else
            {
    #ifdef _X86_
                MemFree(lpBridge);
    #else
                FreeReleayPlace(lpBridge,JUMP_SIZE*6);
    #endif
                lpBridge=NULL;
            }
        }
        return lpBridge;
    }

    static bool WriteRelativeJump(LPVOID lpFrom,LPVOID lpTo)
    {
        bool bRet=false;

        JMP_REL jmp;
        DWORD dwOldProtect;
        VirtualProtect(lpFrom,sizeof(jmp),PAGE_EXECUTE_READWRITE,&dwOldProtect);
        if (SYSLIB_SAFE::CheckParamWrite(lpFrom,sizeof(jmp)))
        {
            jmp.opcode=0xE9;
            jmp.operand=(ULONG_PTR)lpTo-((ULONG_PTR)lpFrom+sizeof(jmp));

            memcpy(lpFrom,&jmp,sizeof(jmp));

            VirtualProtect(lpFrom,sizeof(jmp),dwOldProtect,&dwOldProtect);

            bRet=true;
        }
        return bRet;
    }

    static void DestroyPHOOK(PHOOK_INFO lpHook)
    {
        MemFree(lpHook->lpBackup);
    #ifdef _AMD64_
        FreeReleayPlace(lpHook->lpBridge,JUMP_SIZE*6);
        FreeReleayPlace(lpHook->lpRelay,RAX_JUMP_SIZE);
        MemFree(lpHook->lpTable);
    #else
        MemFree(lpHook->lpBridge);
    #endif
        MemFree(lpHook->lpStub);
        MemFree(lpHook);
        return;
    }

    bool Splice_PathFunc(PHOOK_INFO lpHook)
    {
        bool bRet=false;
        do
        {
            if (!lpHook)
                break;

    #ifdef _AMD64_
            if (!WriteAbsoluteJump(lpHook->lpRelay,lpHook->lpStub))
                break;

            if (!WriteRelativeJump(lpHook->lpRealFunc,lpHook->lpRelay))
                break;
    #else
            if (!WriteRelativeJump(lpHook->lpRealFunc,lpHook->lpStub))
                break;
    #endif

            FlushInstructionCache(GetCurrentProcess(),NULL,0);
            bRet=true;
        }
        while (false);

        return bRet;
    }

    #ifdef _X86_
    static HOOK_STUB Stub=
    {
        DEBUG_OPCODE,

        0x60,                                 /// pusha
        {0x8B,0x54,0x24,0x20},                /// mov edx,[esp+8*4]
        {
            0xB9,                             /// mov ecx,lpAPI
            0x00000000,
        },
        {
            0xB8,                             /// mov eax,lpGetHandlerAddress
            0x00000000,
        },
        0xD0FF,                               /// call eax
        {0x89,0x44,0x24,0x20},                /// mov [esp+8*4],eax
        0x61,                                 /// popa

        0x58,                                 /// pop eax
        0xD0FF,                               /// call eax

        0x50,                                 /// push eax
        0x60,                                 /// pusha
        {
            0xB9,                             /// mov ecx,lpAPI
            0x00000000,
        },
        {
            0xB8,                             /// mov eax,lpEnableHookForCallingThread
            0x00000000,
        },
        0xD0FF,                               /// call eax
        {0x89,0x44,0x24,0x20},                /// mov [esp+8*4],eax
        0x61,                                 /// popa
        0xC3                                  /// retn
    };
    #else
    static HOOK_STUB Stub=
    {
        DEBUG_OPCODE,

        0x58,                                 /// pop rax

        0x51,                                 /// push rcx
        0x52,                                 /// push rdx
        0x5041,                               /// push r8
        0x5141,                               /// push r9

        {0x48,0x89,0xC2},                     /// mov rdx,rax
        {
            0xB948,                           /// mov rcx,lpAPI
            0x0000000000000000,
        },
        {
            0xB848,                           /// mov rax,lpGetHandlerAddress
            0x0000000000000000,
        },
        {0x48,0x83,0xEC,0x20},                /// sub rsp,0x20
        0xD0FF,                               /// call rax
        {0x48,0x83,0xC4,0x20},                /// add rsp,0x20

        0x5941,                               /// pop r9
        0x5841,                               /// pop r8
        0x5A,                                 /// pop rdx
        0x59,                                 /// pop rcx

        0xD0FF,                               /// call rax

        0x50,                                 /// push rax
        0x50,                                 /// push rax
        {
            0xB948,                           /// mov rcx,lpAPI
            0x0000000000000000,
        },
        {
            0xB848,                           /// mov rax,lpEnableHookForCallingThread
            0x0000000000000000,
        },
        {0x48,0x83,0xEC,0x20},                /// sub rsp,0x20
        0xD0FF,                               /// call rax
        {0x48,0x83,0xC4,0x20},                /// add rsp,0x20
        {0x48,0x89,0x44,0x24,0x08},           /// mov [rsp+1*8],rax
        0x58,                                 /// pop rax

        0xC3                                  /// retn
    };
    #endif

    PHOOK_INFO Splice_PrepareAndPathFunc(LPVOID lpFunc,LPVOID lpHandler,DWORD dwFlags)
    {
        PHOOK_INFO lpHook=NULL;
        bool bOk=false;
        do
        {
            if (!lpFunc)
                break;

            if (!lpHandler)
                break;

            lpHook=(PHOOK_INFO)MemAlloc(sizeof(HOOK_INFO));
            if (!lpHook)
                break;

            lpHook->bHookEnabled=true;

            lpHook->lpRealFunc=lpFunc;
            lpHook->lpHandler=lpHandler;

            void *lpBackup=MemQuickAlloc(SPLICE_BACKUP_SIZE);
            if (!lpBackup)
                break;

            lpHook->lpBackup=lpBackup;

            HOOK_STUB *lpStub=(HOOK_STUB*)MemQuickAlloc(sizeof(Stub));
            if (!lpStub)
                break;

            lpHook->lpStub=lpStub;

            memcpy(lpStub,&Stub,sizeof(Stub));

            lpStub->s1.lpAPI=lpFunc;
            lpStub->s3.lpAPI=lpFunc;

            lpStub->s2.lpGetHandlerAddress=GetHandlerAddress;
            lpStub->s4.lpEnableHookForCallingThread=EnableHookForCallingThread;

            DWORD dwTmp;
            VirtualProtect(lpStub,sizeof(*lpStub),PAGE_EXECUTE_READWRITE,&dwTmp);

    #ifdef _AMD64_
            ULONG_PTR *lpTable=(ULONG_PTR *)GetPlaceForRelay(lpFunc,sizeof(ULONG_PTR)*MAX_JUMPS);
            if (!lpTable)
                break;

            lpHook->lpTable=lpTable;

            void *lpRelay=GetPlaceForRelay(lpFunc,RAX_JUMP_SIZE);
            if (!lpRelay)
                break;

            lpHook->lpRelay=lpRelay;
    #endif

            void *lpBridge=CreateBridge(lpFunc,lpBackup,&lpHook->dwBackupCodeSize
    #ifdef _AMD64_
            ,lpTable
    #endif
            );
            if (!lpBridge)
                break;

            lpHook->lpBridge=lpBridge;

            bOk=Splice_PathFunc(lpHook);
        }
        while (false);

        if (!bOk)
        {
            DestroyPHOOK(lpHook);
            lpHook=NULL;
        }

        return lpHook;
    }

    bool Splice_UnpathFunc(PHOOK_INFO lpHook)
    {
        bool bRet=false;
        do
        {
            DWORD dwOldProt;
            VirtualProtect(lpHook->lpRealFunc,lpHook->dwBackupCodeSize,PAGE_EXECUTE_READWRITE,&dwOldProt);
            if (!SYSLIB_SAFE::CheckParamWrite(lpHook->lpRealFunc,lpHook->dwBackupCodeSize))
                break;

            memcpy(lpHook->lpRealFunc,lpHook->lpBackup,lpHook->dwBackupCodeSize);

            FlushInstructionCache(GetCurrentProcess(),NULL,0);
            VirtualProtect(lpHook->lpRealFunc,lpHook->dwBackupCodeSize,dwOldProt,&dwOldProt);

    #ifdef _AMD64_
            VirtualProtect(lpHook->lpRelay,RAX_JUMP_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProt);
            if (!SYSLIB_SAFE::CheckParamWrite(lpHook->lpRelay,RAX_JUMP_SIZE))
                break;

            memset(lpHook->lpRelay,0,RAX_JUMP_SIZE);
            VirtualProtect(lpHook->lpRelay,RAX_JUMP_SIZE,dwOldProt,&dwOldProt);
    #endif

            FlushInstructionCache(GetCurrentProcess(),NULL,0);
            bRet=true;
        }
        while (false);

        return bRet;
    }
}


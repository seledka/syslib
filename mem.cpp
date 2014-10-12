#include "sys_includes.h"
#include "system\system.h"
#include "mem.h"

static HANDLE hHeap;
static DWORD dwInit;

static bool IsInit()
{
    return (dwInit == GetCurrentProcessId());
}

static bool CheckBlock(LPCVOID lpMem)
{
	bool bRet=false;
	if (lpMem)
    {
        LPBYTE p=(LPBYTE)lpMem-sizeof(DWORD)*2;
        if (HeapValidate(hHeap,0,p))
        {
            __try
            {
                DWORD dwSize=*(LPDWORD)p,
                      *b=(LPDWORD)&p[sizeof(DWORD)],
                      *e=(LPDWORD)&p[sizeof(DWORD)*2+dwSize];

                if ((*b == BLOCK_ALLOCED) && (*e == BLOCK_ALLOCED))
                    bRet=true;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
	return bRet;
}

static bool IsHeap(HANDLE hHeap)
{
    bool bRet=false;

    HANDLE hHeaps[256];
    DWORD dwCount=GetProcessHeaps(255,hHeaps);
    if ((dwCount) && (dwCount < 256))
    {
        for (DWORD i=0; i < dwCount; i++)
        {
            if (hHeaps[i] == hHeap)
            {
                bRet=true;
                break;
            }
        }
    }
    return bRet;
}

static void MemInit()
{
    if ((!IsInit()) || (!IsHeap(hHeap)))
    {
        hHeap=HeapCreate(0,0,0);
        if (hHeap)
        {
            DWORD dwHeapInfo=HEAP_LFH;
            HeapSetInformation(hHeap,HeapCompatibilityInformation,&dwHeapInfo,sizeof(dwHeapInfo));
            dwInit=GetCurrentProcessId();
        }
    }
    return;
}

static LPVOID InitMemBlock(LPBYTE lpMem,size_t dwSize)
{
    *(LPDWORD)lpMem=(DWORD)dwSize;
    *(LPDWORD)&lpMem[sizeof(DWORD)]=BLOCK_ALLOCED;
    *(LPDWORD)&lpMem[dwSize+sizeof(DWORD)*2]=BLOCK_ALLOCED;
    return (LPVOID)(lpMem+sizeof(DWORD)*2);
}

static LPVOID MemAllocEx(size_t dwSize,DWORD dwFlags)
{
    DWORD dwGLE=GetLastError();

    if (!IsInit())
        MemInit();

    LPVOID lpMem=NULL;
	if (dwSize)
	{
	    dwSize=RALIGN(dwSize+MEM_SAFE_BYTES,sizeof(DWORD_PTR));
		LPBYTE lpTmp=(LPBYTE)HeapAlloc(hHeap,dwFlags,dwSize+sizeof(DWORD)*3);
		if (lpTmp)
            lpMem=InitMemBlock(lpTmp,dwSize);
    }

    if (lpMem)
        SetLastError(dwGLE);
    return lpMem;
}

SYSLIBFUNC(LPVOID) MemAlloc(size_t dwSize)
{
    return MemAllocEx(dwSize,HEAP_ZERO_MEMORY);
}

SYSLIBFUNC(LPVOID) MemQuickAlloc(size_t dwSize)
{
    return MemAllocEx(dwSize,0);
}

static size_t MemGetBlockSize(LPVOID lpMem)
{
    LPBYTE p=(LPBYTE)lpMem-sizeof(DWORD)*2;
    return *(LPDWORD)p;
}

SYSLIBFUNC(LPVOID) MemRealloc(LPVOID lpMem,size_t dwSize)
{
    DWORD dwGLE=GetLastError();

    if (!IsInit())
        MemInit();

    LPVOID lpNewMem=NULL;
    do
    {
        if (!dwSize)
            break;

        dwSize=RALIGN(dwSize+MEM_SAFE_BYTES,sizeof(DWORD_PTR));

        LPBYTE lpTmp=NULL;
        if (lpMem)
        {
            if (!CheckBlock(lpMem))
                break;

            if (dwSize <= MemGetBlockSize(lpMem))
            {
                lpNewMem=lpMem;
                break;
            }

            lpTmp=(LPBYTE)lpMem-sizeof(DWORD)*2;
        }

        if (lpTmp)
            lpTmp=(LPBYTE)HeapReAlloc(hHeap,HEAP_ZERO_MEMORY,lpTmp,dwSize+sizeof(DWORD)*3);
        else
            lpTmp=(LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSize+sizeof(DWORD)*3);

        if (lpTmp)
            lpNewMem=InitMemBlock(lpTmp,dwSize);
    }
    while (false);

    SetLastError(dwGLE);
    return lpNewMem;
}

SYSLIBFUNC(void) MemFree(LPVOID lpMem)
{
    if (!IsInit())
        return;

    DWORD dwGLE=GetLastError();

    if (CheckBlock(lpMem))
    {
        LPBYTE lpTmp=(LPBYTE)lpMem-sizeof(DWORD)*2;
        DWORD dwSize=*(LPDWORD)lpTmp;
        *(LPDWORD)&lpTmp[sizeof(DWORD)]=BLOCK_FREED;
        *(LPDWORD)&lpTmp[dwSize+sizeof(DWORD)*2]=BLOCK_FREED;
        HeapFree(hHeap,0,lpTmp);
    }

    SetLastError(dwGLE);
    return;
}

SYSLIBFUNC(void) MemZeroAndFree(LPVOID lpMem)
{
    if (!IsInit())
        return;

    DWORD dwGLE=GetLastError();

    if (CheckBlock(lpMem))
    {
        DWORD dwSize=*(LPDWORD)((LPBYTE)lpMem-sizeof(DWORD)*2);
        memset(lpMem,0,dwSize);
        MemFree(lpMem);
    }

    SetLastError(dwGLE);
    return;
}

SYSLIBFUNC(LPVOID) MemCopyEx(LPCVOID lpMem,size_t dwSize)
{
    LPVOID lpNewMem=NULL;
    do
    {
        lpNewMem=MemQuickAlloc(dwSize);
        if (!lpNewMem)
            break;

        __try {
            memcpy(lpNewMem,lpMem,dwSize);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            MemFree(lpNewMem);
            lpNewMem=NULL;
        }
    }
    while (false);
    return lpNewMem;
}

SYSLIBFUNC(void) MemFreeArrayOfPointers(LPVOID *lppMem,DWORD dwCount)
{
    do
    {
        if (!dwCount)
            break;

        if (!SYSLIB_SAFE::CheckParamWrite(lppMem,sizeof(sizeof(*lppMem)*dwCount)))
            break;

        for (DWORD i=0; i < dwCount; i++)
            MemFree(lppMem[i]);

        MemFree(lppMem);
    }
    while (false);
    return;
}


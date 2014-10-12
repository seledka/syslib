#include "sys_includes.h"

#include "syslib\system.h"
#include "syslib\mem.h"

#include "waitformultipleobjects.h"

static void WaitForMultipleObjects_Thread(PWAIT_FOR_MULTIPLE_OBJECTS_THREAD lpWaitInfo)
{
    DWORD dwMilliseconds=1;
    if (lpWaitInfo->bWaitAll)
        dwMilliseconds=lpWaitInfo->dwMilliseconds;

    while (WaitForSingleObject(lpWaitInfo->hStopEvent,0) == WAIT_TIMEOUT)
    {
        DWORD dwRet=WaitForMultipleObjects(lpWaitInfo->nCount,lpWaitInfo->Handles,lpWaitInfo->bWaitAll,dwMilliseconds);
        if (dwRet != WAIT_TIMEOUT)
        {
            if (!lpWaitInfo->bWaitAll)
                SetEvent(lpWaitInfo->hStopEvent);

            lpWaitInfo->dwRet=dwRet;
            break;
        }

        if (dwMilliseconds == lpWaitInfo->dwMilliseconds)
        {
            lpWaitInfo->dwRet=WAIT_TIMEOUT;
            break;
        }

        if (lpWaitInfo->dwMilliseconds != INFINITE)
            lpWaitInfo->dwMilliseconds--;
    }
    return;
}

SYSLIBFUNC(DWORD) SysWaitForMultipleObjects(DWORD nCount,const PHANDLE lpHandles,BOOL bWaitAll,DWORD dwMilliseconds)
{
    if (!SYSLIB_SAFE::CheckParamRead(lpHandles,sizeof(HANDLE)*nCount))
        return 0;

    DWORD dwRet=0;
    if (nCount > MAXIMUM_WAIT_OBJECTS)
    {
        HANDLE hStopEvent=CreateEvent(NULL,true,false,NULL);
        if (hStopEvent)
        {
            DWORD dwThreadsCount=nCount/MAXIMUM_WAIT_OBJECTS;
            if (nCount % MAXIMUM_WAIT_OBJECTS)
                dwThreadsCount++;

            HANDLE *lpThreads=(HANDLE*)MemQuickAlloc(dwThreadsCount*sizeof(HANDLE));
            if (lpThreads)
            {
                byte *lpWaitStructs=(byte*)MemAlloc(dwThreadsCount*sizeof(WAIT_FOR_MULTIPLE_OBJECTS_THREAD));
                if (lpWaitStructs)
                {
                    DWORD dwCount=nCount;
                    for (DWORD i=0; i < dwThreadsCount; i++)
                    {
                        PWAIT_FOR_MULTIPLE_OBJECTS_THREAD lpWaitInfo=(PWAIT_FOR_MULTIPLE_OBJECTS_THREAD)lpWaitStructs[i*sizeof(WAIT_FOR_MULTIPLE_OBJECTS_THREAD)];

                        lpWaitInfo->hStopEvent=hStopEvent;
                        lpWaitInfo->dwPosition=i*MAXIMUM_WAIT_OBJECTS;
                        lpWaitInfo->nCount=min(dwCount,MAXIMUM_WAIT_OBJECTS);
                        memcpy(lpWaitInfo->Handles[lpWaitInfo->dwPosition],lpHandles[lpWaitInfo->dwPosition],lpWaitInfo->nCount*sizeof(HANDLE));
                        lpWaitInfo->bWaitAll=bWaitAll;
                        lpWaitInfo->dwMilliseconds=dwMilliseconds;
                        lpWaitInfo->dwRet=(DWORD)-2;

                        lpThreads[i]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)WaitForMultipleObjects_Thread,lpWaitInfo,0,NULL);
                        dwCount-=lpWaitInfo->nCount;
                    }

                    WaitForMultipleObjects(dwThreadsCount,lpThreads,bWaitAll,INFINITE);

                    if (bWaitAll)
                    {
                        /**
                            если нужно дождаться всех объектов - проверяем,
                            так ли это
                        **/
                        for (DWORD i=0; i < dwThreadsCount; i++)
                        {
                            PWAIT_FOR_MULTIPLE_OBJECTS_THREAD lpWaitInfo=(PWAIT_FOR_MULTIPLE_OBJECTS_THREAD)lpWaitStructs[i*sizeof(WAIT_FOR_MULTIPLE_OBJECTS_THREAD)];
                            if ((lpWaitInfo->dwRet == WAIT_TIMEOUT) || (lpWaitInfo->dwRet == WAIT_FAILED))
                            {
                                dwRet=lpWaitInfo->dwRet;
                                break;
                            }

                            dwRet=lpWaitInfo->dwRet;
                        }
                    }
                    else
                    {
                        /// ищем индекс первого "правильного" элемента

                        for (DWORD i=0; i < dwThreadsCount; i++)
                        {
                            PWAIT_FOR_MULTIPLE_OBJECTS_THREAD lpWaitInfo=(PWAIT_FOR_MULTIPLE_OBJECTS_THREAD)lpWaitStructs[i*sizeof(WAIT_FOR_MULTIPLE_OBJECTS_THREAD)];
                            if ((lpWaitInfo->dwRet >= WAIT_OBJECT_0) && (lpWaitInfo->dwRet <= WAIT_OBJECT_0+MAXIMUM_WAIT_OBJECTS))
                            {
                                dwRet=lpWaitInfo->dwRet+lpWaitInfo->dwPosition;
                                break;
                            }
                        }
                    }

                    for (DWORD i=0; i < dwThreadsCount; i++)
                        SysCloseHandle(lpThreads[i]);

                    MemFree(lpWaitStructs);
                }
                MemFree(lpThreads);
            }
            SysCloseHandle(hStopEvent);
        }
    }
    else
        dwRet=WaitForMultipleObjects(nCount,lpHandles,bWaitAll,dwMilliseconds);

    return dwRet;
}


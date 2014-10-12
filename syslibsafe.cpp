#include "sys_includes.h"

namespace SYSLIB_SAFE
{
    bool CheckCodePtr(LPVOID lpFunc)
    {
        bool bRet=false;
        do
        {
            if (!lpFunc)
                break;

            if (IsBadCodePtr((FARPROC)lpFunc))
                break;

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckParamRead(LPVOID lpParam,DWORD dwSize)
    {
        bool bRet=false;
        do
        {
            if (!dwSize)
                break;

            if (!lpParam)
                break;

            if (IsBadReadPtr(lpParam,dwSize))
                break;

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckParamWrite(LPVOID lpParam,DWORD dwSize)
    {
        bool bRet=false;
        do
        {
            if (!dwSize)
                break;

            if (!lpParam)
                break;

            if (IsBadWritePtr(lpParam,dwSize))
                break;

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckStrParamW(LPCWSTR lpSource,DWORD dwSourceSize)
    {
        bool bRet=false;
        do
        {
            if (!lpSource)
                break;

            if (IsBadStringPtrW(lpSource,(dwSourceSize) ? dwSourceSize : SYSLIB_STR_MAX_LEN))
                break;

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckStrParamsExW(LPCWSTR lpSource,DWORD dwSourceSize,LPDWORD *lppOutSize)
    {
        bool bRet=false;
        do
        {
            if (!CheckStrParamW(lpSource,dwSourceSize))
                break;

            if (*lppOutSize)
            {
                if (IsBadWritePtr(*lppOutSize,sizeof(**lppOutSize)))
                    *lppOutSize=NULL;
            }

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckStrParamA(LPCSTR lpSource,DWORD dwSourceSize)
    {
        bool bRet=false;
        do
        {
            if (!lpSource)
                break;

            if (IsBadStringPtrA(lpSource,(dwSourceSize) ? dwSourceSize : SYSLIB_STR_MAX_LEN))
                break;

            bRet=true;
        }
        while (false);
        return bRet;
    }

    bool CheckStrParamsExA(LPCSTR lpSource,DWORD dwSourceSize,LPDWORD *lppOutSize)
    {
        bool bRet=false;
        do
        {
            if (!CheckStrParamA(lpSource,dwSourceSize))
                break;

            if (*lppOutSize)
            {
                if (IsBadWritePtr(*lppOutSize,sizeof(**lppOutSize)))
                    *lppOutSize=NULL;
            }

            bRet=true;
        }
        while (false);
        return bRet;
    }
}


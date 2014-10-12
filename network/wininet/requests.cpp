#include "sys_includes.h"
#include <wininet.h>
#include <shlwapi.h>

#include "syslib\utils.h"
#include "syslib\debug.h"
#include "syslib\base64.h"
#include "syslib\system.h"
#include "syslib\net.h"
#include "syslib\str.h"
#include "syslib\mem.h"
#include "syslib\criticalsections.h"

#include "http.h"
#include "argslist.h"
#include "requests.h"

#include "syslib\strcrypt.h"
#include "str_crx.h"

namespace SYSLIB
{
        static void FreeFormData(FORM_DATA *lpForm,bool bSelfFree)
    {
        MemFree(lpForm->lpFormPostfix);
        MemFree(lpForm->lpFormPrefix);
        MemFree(lpForm->feFormElement.lpElementData);
        if (bSelfFree)
            MemFree(lpForm);
        return;
    }

    static void FreeRequestData(COMPILED_REQUEST *lpData)
    {
        if (lpData->bFormData)
        {
            FORM_DATA *lpFrm=lpData->fdFormElements.lpNext;
            FreeFormData(&lpData->fdFormElements,false);

            while (lpFrm)
            {
                FORM_DATA *lpNext=lpFrm->lpNext;
                FreeFormData(lpFrm,true);
                lpFrm=lpNext;
            }
        }
        else
            MemFree(lpData->reBinaryElement.lpElementData);

        MemFree(lpData);
        return;
    }

    static bool EncodeTextArgument(HTTP_REQUEST_HANDLE *lpReq,char **lppBuffer,DWORD *lpSize)
    {
        bool bRet=false;
        do
        {
            char *lpBuffer=*lppBuffer;
            DWORD dwBufSize=*lpSize;

            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_USE_UTF8)
            {
                char *lpUtf8=StrAnsiToUtf8Ex(lpBuffer,dwBufSize,&dwBufSize);
                if (!lpUtf8)
                    break;

                MemFree(lpBuffer);

                lpBuffer=lpUtf8;
            }

            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_URL_ENCODE)
            {
                char *lpEncoded=NetUrlEncodeBufferExA(lpBuffer,dwBufSize,&dwBufSize);
                if (!lpEncoded)
                    break;

                MemFree(lpBuffer);

                lpBuffer=lpEncoded;
            }

            *lppBuffer=lpBuffer;
            *lpSize=dwBufSize;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool HandleBinaryArgumentAsText(HTTP_REQUEST_HANDLE *lpReq,INET_ARG *lpArg,char **lppBuffer,DWORD *lpBuffSize)
    {
        bool bRet=false;
        do
        {
            if ((!lppBuffer) || (!lpBuffSize) || (!lpReq) || (!lpArg))
                break;

            if (lpArg->dwType != INET_ARG_RAW)
                break;

            if (!(lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE))
                break;

            byte *lpBuf=(byte *)lpArg->lpValueRaw;
            DWORD dwBufSize=lpArg->dwValueRawSize;
            char *lpBase64=Base64_EncodeExA(lpBuf,dwBufSize,&dwBufSize,0);
            if (!lpBase64)
                break;

            *lppBuffer=lpBase64;
            *lpBuffSize=dwBufSize;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool ReadFileArgumentInt(INET_ARG *lpArg,char **lppBuffer,DWORD *lpBuffSize)
    {
        bool bRet=false;
        do
        {
            char *lpBuf=NULL;
            DWORD dwBufSize=0;

            if (!lpArg->pseudo_file.lpValueRaw)
            {
                HANDLE hFile=CreateFileA(lpArg->lpFullFileName,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
                if (hFile == INVALID_HANDLE_VALUE)
                    break;

                DWORD dwFileSize=GetFileSize(hFile,NULL);
                lpBuf=(char*)MemQuickAlloc(dwFileSize);
                if (!lpBuf)
                {
                    SysCloseHandle(hFile);
                    break;
                }

                bool bRead=((ReadFile(hFile,lpBuf,dwFileSize,&dwBufSize,NULL)) && (dwFileSize == dwBufSize));

                SysCloseHandle(hFile);

                if (!bRead)
                {
                    MemFree(lpBuf);
                    break;
                }
            }
            else
            {
                lpBuf=(char*)MemQuickAlloc(lpArg->pseudo_file.dwValueRawSize);
                if (!lpBuf)
                    break;

                memcpy(lpBuf,lpArg->pseudo_file.lpValueRaw,lpArg->pseudo_file.dwValueRawSize);
                dwBufSize=lpArg->pseudo_file.dwValueRawSize;
            }

            *lppBuffer=lpBuf;
            *lpBuffSize=dwBufSize;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool HandleFileArgumentAsText(HTTP_REQUEST_HANDLE *lpReq,INET_ARG *lpArg,char **lppBuffer,DWORD *lpBuffSize)
    {
        bool bRet=false;
        do
        {
            if ((!lppBuffer) || (!lpBuffSize) || (!lpReq) || (!lpArg))
                break;

            if (lpArg->dwType != INET_ARG_FILE)
                break;

            char *lpContentType=(char *)NetGetFileContentTypeA(lpArg->lpFullFileName);
            bool bText=(StrCmpNIA(lpContentType,dcrA_c624ae24("text"),4) == 0);
            MemFree(lpContentType);

            if ((!bText) && (!(lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)))
                break;

            char *lpBuf=NULL;
            DWORD dwBufSize=0;

            if (!ReadFileArgumentInt(lpArg,&lpBuf,&dwBufSize))
                break;

            if (!bText)
            {
                INET_ARG arg;
                arg.dwType=INET_ARG_RAW;
                arg.lpValueRaw=lpBuf;
                arg.dwValueRawSize=dwBufSize;
                if (!HandleBinaryArgumentAsText(lpReq,&arg,&lpBuf,&dwBufSize))
                {
                    MemFree(lpBuf);
                    break;
                }
                MemFree(arg.lpValueRaw);
            }

            *lppBuffer=lpBuf;
            *lpBuffSize=dwBufSize;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool HandleBinaryArgumentAsBinary(HTTP_REQUEST_HANDLE *lpReq,INET_ARG *lpArg,char **lppBuffer,DWORD *lpBuffSize)
    {
        bool bRet=false;
        do
        {
            if ((!lppBuffer) || (!lpBuffSize) || (!lpReq) || (!lpArg))
                break;

            if (lpArg->dwType != INET_ARG_RAW)
                break;

            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)
                break;

            char *lpBuf=(char*)MemQuickAlloc(lpArg->dwValueRawSize);
            if (!lpBuf)
                break;

            memcpy(lpBuf,lpArg->lpValueRaw,lpArg->dwValueRawSize);

            *lppBuffer=lpBuf;
            *lpBuffSize=lpArg->dwValueRawSize;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool HandleFileArgumentAsBinary(HTTP_REQUEST_HANDLE *lpReq,INET_ARG *lpArg,char **lppBuffer,DWORD *lpBuffSize)
    {
        bool bRet=false;
        do
        {
            if ((!lppBuffer) || (!lpBuffSize) || (!lpReq) || (!lpArg))
                break;

            if (lpArg->dwType != INET_ARG_FILE)
                break;

            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)
                break;

            if (!ReadFileArgumentInt(lpArg,lppBuffer,lpBuffSize))
                break;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool CompileTextTypeArgument(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST **lppData)
    {
        bool bRet=false;
        do
        {
            char *lpBuf=NULL;
            DWORD dwBufSize=0;

            INET_ARG *lpArg=((INET_ARGS_LIST*)lpReq->hArgsList)->lpArgs;
            if (lpArg->dwType == INET_ARG_STRING)
            {
                lpBuf=StrDuplicateA(lpArg->lpValueStr,0);
                if (!lpBuf)
                    break;

                dwBufSize=lpArg->dwValueStrSize;
            }
            else if (lpArg->dwType == INET_ARG_RAW)
            {
                if (!HandleBinaryArgumentAsText(lpReq,lpArg,&lpBuf,&dwBufSize))
                    break;
            }
            else if (lpArg->dwType == INET_ARG_FILE)
            {
                if (!HandleFileArgumentAsText(lpReq,lpArg,&lpBuf,&dwBufSize))
                    break;
            }

            if (!EncodeTextArgument(lpReq,&lpBuf,&dwBufSize))
            {
                MemFree(lpBuf);
                break;
            }

            COMPILED_REQUEST *lpData=(COMPILED_REQUEST *)MemAlloc(sizeof(COMPILED_REQUEST));
            if (!lpData)
            {
                MemFree(lpBuf);
                break;
            }

            lpData->bFormData=false;
            lpData->dwCompiledRequestSize=dwBufSize;

            lpData->reBinaryElement.dwElementSize=dwBufSize;
            lpData->reBinaryElement.lpElementData=(void*)lpBuf;

            *lppData=lpData;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool CompileBynaryTypeArgument(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST **lppData)
    {
        bool bRet=false;
        do
        {
            char *lpBuf=NULL;
            DWORD dwBufSize=0;

            INET_ARG *lpArg=((INET_ARGS_LIST*)lpReq->hArgsList)->lpArgs;
            if (lpArg->dwType == INET_ARG_STRING)
            {
                lpBuf=StrDuplicateA(lpArg->lpValueStr,0);
                if (!lpBuf)
                    break;

                dwBufSize=lpArg->dwValueStrSize;
            }
            else if (lpArg->dwType == INET_ARG_RAW)
            {
                if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)
                {
                    if (!HandleBinaryArgumentAsText(lpReq,lpArg,&lpBuf,&dwBufSize))
                        break;
                }
                else
                {
                    if (!HandleBinaryArgumentAsBinary(lpReq,lpArg,&lpBuf,&dwBufSize))
                        break;
                }
            }
            else if (lpArg->dwType == INET_ARG_FILE)
            {
                if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)
                {
                    if (!HandleFileArgumentAsText(lpReq,lpArg,&lpBuf,&dwBufSize))
                        break;
                }
                else
                {
                    if (!HandleFileArgumentAsBinary(lpReq,lpArg,&lpBuf,&dwBufSize))
                        break;
                }
            }

            COMPILED_REQUEST *lpData=(COMPILED_REQUEST *)MemAlloc(sizeof(COMPILED_REQUEST));
            if (!lpData)
            {
                MemFree(lpBuf);
                break;
            }

            lpData->bFormData=false;
            lpData->dwCompiledRequestSize=dwBufSize;

            lpData->reBinaryElement.dwElementSize=dwBufSize;
            lpData->reBinaryElement.lpElementData=(void*)lpBuf;

            *lppData=lpData;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static void AddArgumentToRequest(COMPILED_REQUEST *lpRequest,FORM_DATA *lpArgument)
    {
        if (lpRequest->dwCompiledRequestSize)
        {
            FORM_DATA *lpCurFrm=&lpRequest->fdFormElements;
            while (lpCurFrm->lpNext)
                lpCurFrm=lpCurFrm->lpNext;

            lpCurFrm->lpNext=lpArgument;
        }
        else
            memcpy(&lpRequest->fdFormElements,lpArgument,sizeof(*lpArgument));

        lpRequest->dwCompiledRequestSize+=lpArgument->dwFormPrefixSize+lpArgument->dwFormPostfixSize+lpArgument->feFormElement.dwElementSize;
        return;
    }

    static bool CompileFormTypeArguments(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST **lppData)
    {
        bool bRet=false;
        COMPILED_REQUEST *lpData=NULL;
        do
        {
            lpData=(COMPILED_REQUEST *)MemAlloc(sizeof(COMPILED_REQUEST));
            if (!lpData)
                break;

            bool bFirstArgument=true;
            lpData->bFormData=true;

            INET_ARG *lpArg=((INET_ARGS_LIST*)lpReq->hArgsList)->lpArgs;
            while (lpArg)
            {
                char *lpCurArg=NULL;
                DWORD dwCurArgSize=0;

                switch (lpArg->dwType)
                {
                    case INET_ARG_STRING:
                    {
                        lpCurArg=StrDuplicateA(lpArg->lpValueStr,0);
                        if (lpCurArg)
                            dwCurArgSize=lpArg->dwValueStrSize;
                        break;
                    }
                    case INET_ARG_INT:
                    {
                        dwCurArgSize=StrFormatExA(&lpCurArg,dcrA_163268b6("%d"),lpArg->dwValueInt);
                        break;
                    }
                    case INET_ARG_RAW:
                    {
                        HandleBinaryArgumentAsText(lpReq,lpArg,&lpCurArg,&dwCurArgSize);
                        break;
                    }
                    case INET_ARG_FILE:
                    {
                        HandleFileArgumentAsText(lpReq,lpArg,&lpCurArg,&dwCurArgSize);
                        break;
                    }
                }

                do
                {
                    if (!lpCurArg)
                        break;

                    if (!EncodeTextArgument(lpReq,&lpCurArg,&dwCurArgSize))
                    {
                        MemFree(lpCurArg);
                        break;
                    }

                    FORM_DATA *lpForm=(FORM_DATA *)MemAlloc(sizeof(FORM_DATA));
                    if (!lpForm)
                    {
                        MemFree(lpCurArg);
                        break;
                    }

                    lpForm->feFormElement.lpElementData=lpCurArg;
                    lpForm->feFormElement.dwElementSize=dwCurArgSize;

                    DWORD dwPrefixSize=0;
                    char *lpPrefix=NULL;

                    if (bFirstArgument)
                    {
                        dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_dab0b7bc("%s="),lpArg->lpName);
                        if (!dwPrefixSize)
                        {
                            FreeFormData(lpForm,true);
                            break;
                        }
                        bFirstArgument=false;
                    }
                    else
                    {
                        dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_f6133e8a("&%s="),lpArg->lpName);
                        if (!dwPrefixSize)
                        {
                            FreeFormData(lpForm,true);
                            break;
                        }
                    }

                    lpForm->lpFormPrefix=lpPrefix;
                    lpForm->dwFormPrefixSize=dwPrefixSize;

                    AddArgumentToRequest(lpData,lpForm);
                }
                while (false);

                lpArg=lpArg->lpNext;
            }

            if (!lpData->dwCompiledRequestSize)
            {
                FreeRequestData(lpData);
                break;
            }

            *lppData=lpData;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool AddFiles(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST *lpCompiledRequest,INET_ARG *lpFile,FORM_DATA **lppLastForm)
    {
        bool bRet=false;

        /// добавляем файл....
        if (!lpFile->lpNextFile)
        {
            char *lpContentType=NULL;
            do
            {
                char *lpCurArg=NULL;
                DWORD dwCurArgSize=0;
                if (!HandleFileArgumentAsBinary(lpReq,lpFile,&lpCurArg,&dwCurArgSize))
                    break;

                FORM_DATA *lpForm=(FORM_DATA *)MemAlloc(sizeof(FORM_DATA));
                if (!lpForm)
                {
                    MemFree(lpCurArg);
                    break;
                }

                lpForm->feFormElement.lpElementData=lpCurArg;
                lpForm->feFormElement.dwElementSize=dwCurArgSize;

                lpContentType=(char *)NetGetFileContentTypeA(lpFile->lpFullFileName);
                if (!lpContentType)
                {
                    FreeFormData(lpForm,true);
                    break;
                }

                DWORD dwFullFileNameSize=lpFile->dwFileNameSize,
                      dwFileNameSize=0;

                char *lpFileName=lpFile->lpFullFileName+dwFullFileNameSize;
                while (dwFullFileNameSize--)
                {
                    if (*(lpFileName-1) == '\\')
                        break;

                    lpFileName--;
                    dwFileNameSize++;
                }

                char *lpPrefix;
                DWORD dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_e9fe3776("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"),lpReq->szMultipartBoundary,lpFile->lpName,lpFileName,lpContentType);
                if (!dwPrefixSize)
                {
                    FreeFormData(lpForm,true);
                    break;
                }

                lpForm->lpFormPrefix=lpPrefix;
                lpForm->dwFormPrefixSize=dwPrefixSize;

                char *lpPostfix=StrDuplicateA(dcrA_0f7b6850("\r\n"),0);
                if (!lpPostfix)
                {
                    FreeFormData(lpForm,true);
                    break;
                }

                lpForm->dwFormPostfixSize=sizeof("\r\n")-1;
                lpForm->lpFormPostfix=lpPostfix;

                AddArgumentToRequest(lpCompiledRequest,lpForm);
                *lppLastForm=lpForm;

                bRet=true;
             }
             while (false);

             MemFree(lpContentType);
        }
        /// добавляем пачку файлов...
        else
        {
            char szMixedBoundary[40];

            LARGE_INTEGER liBoundary={GetRndDWORD(),GetRndDWORD()};
            DWORD dwMixedBoundarySize=StrFormatA(szMixedBoundary,dcrA_d6855130("%I64X"),liBoundary.QuadPart),
                  dwDataSize=0;
            do
            {
                FORM_DATA *lpForm=(FORM_DATA *)MemAlloc(sizeof(FORM_DATA));
                if (!lpForm)
                    break;

                char *lpPrefix;
                DWORD dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_c41371a5("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n"),lpReq->szMultipartBoundary,lpFile->lpName,szMixedBoundary);
                if (!dwPrefixSize)
                {
                    FreeFormData(lpForm,true);
                    break;
                }

                lpForm->lpFormPrefix=lpPrefix;
                lpForm->dwFormPrefixSize=dwPrefixSize;

                dwDataSize+=lpForm->dwFormPrefixSize;

                FORM_DATA *lpLastForm=lpForm;
                INET_ARG *lpCurFile=lpFile;
                while (lpCurFile)
                {
                    char *lpContentType=NULL;
                    do
                    {
                        char *lpCurArg=NULL;
                        DWORD dwCurArgSize=0;
                        if (!HandleFileArgumentAsBinary(lpReq,lpCurFile,&lpCurArg,&dwCurArgSize))
                            break;

                        FORM_DATA *lpCurForm=(FORM_DATA *)MemAlloc(sizeof(FORM_DATA));
                        if (!lpCurForm)
                        {
                            MemFree(lpCurArg);
                            break;
                        }

                        lpCurForm->feFormElement.lpElementData=lpCurArg;
                        lpCurForm->feFormElement.dwElementSize=dwCurArgSize;

                        lpContentType=(char *)NetGetFileContentTypeA(lpCurFile->lpFullFileName);
                        if (!lpContentType)
                        {
                            FreeFormData(lpCurForm,true);
                            break;
                        }

                        DWORD dwFullFileNameSize=lpCurFile->dwFileNameSize,
                              dwFileNameSize=0;

                        char *lpFileName=lpCurFile->lpFullFileName+dwFullFileNameSize;
                        while (dwFullFileNameSize--)
                        {
                            if (*(lpFileName-1) == '\\')
                                break;

                            lpFileName--;
                            dwFileNameSize++;
                        }

                        char *lpPrefix;
                        DWORD dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_3366e109("--%s\r\nContent-Disposition: file; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"),szMixedBoundary,lpFileName,lpContentType);
                        if (!dwPrefixSize)
                        {
                            FreeFormData(lpCurForm,true);
                            break;
                        }

                        lpCurForm->lpFormPrefix=lpPrefix;
                        lpCurForm->dwFormPrefixSize=dwPrefixSize;

                        char *lpPostfix=StrDuplicateA(dcrA_0f7b6850("\r\n"),0);
                        if (!lpPostfix)
                        {
                            FreeFormData(lpCurForm,true);
                            break;
                        }

                        lpCurForm->dwFormPostfixSize=sizeof("\r\n")-1;
                        lpCurForm->lpFormPostfix=lpPostfix;

                        dwDataSize+=lpCurForm->dwFormPrefixSize;
                        dwDataSize+=lpCurForm->dwFormPostfixSize;
                        dwDataSize+=dwCurArgSize;

                        lpLastForm->lpNext=lpCurForm;
                        lpLastForm=lpCurForm;
                    }
                    while (false);

                    MemFree(lpContentType);

                    lpCurFile=lpCurFile->lpNextFile;
                }

                if (lpForm != lpLastForm)
                {
                    char *lpLastPostfix;
                    DWORD dwLastPostfixSize=StrFormatExA(&lpLastPostfix,dcrA_d8e258b3("%s--%s--\r\n"),lpLastForm->lpFormPostfix,szMixedBoundary);
                    if (!dwLastPostfixSize)
                    {
                        while (lpForm)
                        {
                            FORM_DATA *lpNext=lpForm->lpNext;
                            FreeFormData(lpForm,true);
                            lpForm=lpNext;
                        }
                        break;
                    }

                    MemFree(lpLastForm->lpFormPostfix);
                    lpLastForm->lpFormPostfix=lpLastPostfix;

                    dwDataSize=dwDataSize-lpLastForm->dwFormPostfixSize+dwLastPostfixSize;

                    lpCompiledRequest->dwCompiledRequestSize+=dwDataSize;
                    lpLastForm->dwFormPostfixSize=dwLastPostfixSize;

                    AddArgumentToRequest(lpCompiledRequest,lpForm);
                    *lppLastForm=lpLastForm;
                }
                else
                    FreeFormData(lpForm,true);
            }
            while (false);
        }

        return bRet;
    }

    static bool CompileMultipartFormTypeArguments(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST **lppData)
    {
        bool bRet=false;
        COMPILED_REQUEST *lpData=NULL;
        do
        {
            lpData=(COMPILED_REQUEST *)MemAlloc(sizeof(COMPILED_REQUEST));
            if (!lpData)
                break;

            lpData->bFormData=true;

            FORM_DATA *lpLastForm=NULL;
            INET_ARG *lpArg=((INET_ARGS_LIST*)lpReq->hArgsList)->lpArgs;
            while (lpArg)
            {
                char *lpCurArg=NULL;
                DWORD dwCurArgSize=0;

                switch (lpArg->dwType)
                {
                    case INET_ARG_STRING:
                    {
                        lpCurArg=StrDuplicateA(lpArg->lpValueStr,0);
                        if (lpCurArg)
                            dwCurArgSize=lpArg->dwValueStrSize;
                        break;
                    }
                    case INET_ARG_INT:
                    {
                        dwCurArgSize=StrFormatExA(&lpCurArg,dcrA_163268b6("%d"),lpArg->dwValueInt);
                        break;
                    }
                    case INET_ARG_RAW:
                    {
                        HandleBinaryArgumentAsBinary(lpReq,lpArg,&lpCurArg,&dwCurArgSize);
                        break;
                    }
                    case INET_ARG_FILE:
                    {
                        AddFiles(lpReq,lpData,lpArg,&lpLastForm);
                        break;
                    }
                }

                do
                {
                    if (!lpCurArg)
                        break;

                    FORM_DATA *lpForm=(FORM_DATA *)MemAlloc(sizeof(FORM_DATA));
                    if (!lpForm)
                    {
                        MemFree(lpCurArg);
                        break;
                    }

                    lpForm->feFormElement.lpElementData=lpCurArg;
                    lpForm->feFormElement.dwElementSize=dwCurArgSize;

                    char *lpPrefix;
                    DWORD dwPrefixSize=StrFormatExA(&lpPrefix,dcrA_f50e7125("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n"),lpReq->szMultipartBoundary,lpArg->lpName);
                    if (!dwPrefixSize)
                    {
                        FreeFormData(lpForm,true);
                        break;
                    }

                    lpForm->lpFormPrefix=lpPrefix;
                    lpForm->dwFormPrefixSize=dwPrefixSize;

                    char *lpPostfix=StrDuplicateA(dcrA_0f7b6850("\r\n"),0);
                    if (!lpPostfix)
                    {
                        FreeFormData(lpForm,true);
                        break;
                    }

                    lpForm->dwFormPostfixSize=sizeof("\r\n")-1;
                    lpForm->lpFormPostfix=lpPostfix;

                    AddArgumentToRequest(lpData,lpForm);
                    lpLastForm=lpForm;
                }
                while (false);

                lpArg=lpArg->lpNext;
            }

            if (!lpData->dwCompiledRequestSize)
            {
                FreeRequestData(lpData);
                break;
            }

            char *lpLastPostfix;
            DWORD dwLastPostfixSize=StrFormatExA(&lpLastPostfix,dcrA_d8e258b3("%s--%s--\r\n"),lpLastForm->lpFormPostfix,lpReq->szMultipartBoundary);
            if (!dwLastPostfixSize)
            {
                FreeRequestData(lpData);
                break;
            }

            MemFree(lpLastForm->lpFormPostfix);
            lpLastForm->lpFormPostfix=lpLastPostfix;

            lpData->dwCompiledRequestSize=lpData->dwCompiledRequestSize-lpLastForm->dwFormPostfixSize+dwLastPostfixSize;
            lpLastForm->dwFormPostfixSize=dwLastPostfixSize;

            *lppData=lpData;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool CompileRequest(HTTP_REQUEST_HANDLE *lpReq,COMPILED_REQUEST **lppData)
    {
        bool bRet=false;
        COMPILED_REQUEST *lpData=NULL;
        do
        {
            if (!lppData)
                break;

            *lppData=NULL;

            if (!lpReq->hArgsList)
            {
                bRet=true;
                break;
            }

            INET_ARGS_LIST *lpList=(INET_ARGS_LIST*)lpReq->hArgsList;
            if (lpList->dwType != HTTP_ARGUMENTS_LIST)
                break;

            if (!lpList->lpArgs)
            {
                bRet=true;
                break;
            }

            EnterSafeCriticalSection(&lpList->csArguments);
            {
                switch (lpReq->dwDataType)
                {
                    case HTTP_DATA_TYPE_TEXT:
                    {
                        /**
                            берем в расчет только первый аргумент, т.к. хз что в остальных и как их
                            совмещать вместе
                        **/
                        if (!CompileTextTypeArgument(lpReq,&lpData))
                            break;

                        LPCSTR lpTypeHdr=NULL;
                        if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_USE_UTF8)
                            lpTypeHdr=dcrA_e9bef29c("Content-Type: text/plain; charset=utf-8\r\n");
                        else
                            lpTypeHdr=dcrA_444fbd8a("Content-Type: text/plain\r\n");

                        HttpAddRequestHeadersA(lpReq->hReq,lpTypeHdr,-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
                        break;
                    }
                    case HTTP_DATA_TYPE_UNKNOWN:
                    case HTTP_DATA_TYPE_BINARY:
                    {
                        /**
                            берем в расчет только первый аргумент, т.к. хз что в остальных и как их
                            совмещать вместе
                        **/
                        if (!CompileBynaryTypeArgument(lpReq,&lpData))
                            break;

                        if (lpReq->dwDataType != HTTP_DATA_TYPE_UNKNOWN)
                        {
                            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_BASE64_ENCODE)
                                HttpAddRequestHeadersA(lpReq->hReq,dcrA_758ce255("Content-Transfer-Encoding: base64\r\n"),-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);

                            HttpAddRequestHeadersA(lpReq->hReq,dcrA_ef03d24e("Content-Type: application/octet-stream\r\n"),-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
                        }
                        break;
                    }
                    case HTTP_DATA_TYPE_FORM:
                    {
                        if (!CompileFormTypeArguments(lpReq,&lpData))
                            break;

                        HttpAddRequestHeadersA(lpReq->hReq,dcrA_76f9f733("Content-Type: application/x-www-form-urlencoded\r\n"),-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
                        break;
                    }
                    case HTTP_DATA_TYPE_FORM_MULTIPART:
                    {
                        if (!CompileMultipartFormTypeArguments(lpReq,&lpData))
                            break;

                        char *lpHdr;
                        if (!StrFormatExA(&lpHdr,dcrA_46aadccf("Content-Type: multipart/form-data; boundary=%s\r\n"),lpReq->szMultipartBoundary))
                        {
                            FreeRequestData(lpData);
                            lpData=NULL;
                            break;
                        }

                        HttpAddRequestHeadersA(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
                        MemFree(lpHdr);
                        break;
                    }
                }
            }
            LeaveSafeCriticalSection(&lpList->csArguments);

            if (!lpData)
                break;

            *lppData=lpData;

            bRet=true;
        }
        while (false);

        return bRet;
    }

    static bool WriteRequestData(HINTERNET hRequest,COMPILED_REQUEST *lpReqData)
    {
        bool bRet=false;
        do
        {
            INTERNET_BUFFERSA ib={0};
            ib.dwStructSize=sizeof(ib);
            if (!HttpSendRequestExA(hRequest,&ib,NULL,HSR_INITIATE,NULL))
                break;

            if (lpReqData->bFormData)
            {
                bool bFailed=false;

                FORM_DATA *lpFormElement=&lpReqData->fdFormElements;
                while (lpFormElement)
                {
                    DWORD dwWrite=0;
                    if (lpFormElement->lpFormPrefix)
                    {
                        /**
                            т.к. все заголовки уже составлены в "скомпилированном" запросе, нам
                            нет нужды возиться с этим геморроем, просто последовательно записываем
                            префиксы форм и их данные (если таковые имеются)
                        **/
                        if (!InternetWriteFile(hRequest,lpFormElement->lpFormPrefix,lpFormElement->dwFormPrefixSize,&dwWrite))
                        {
                            bFailed=true;
                            break;
                        }
                    }

                    if (lpFormElement->feFormElement.lpElementData)
                    {
                        if (!InternetWriteFile(hRequest,lpFormElement->feFormElement.lpElementData,lpFormElement->feFormElement.dwElementSize,&dwWrite))
                        {
                            bFailed=true;
                            break;
                        }
                    }

                    if (lpFormElement->lpFormPostfix)
                    {
                        if (!InternetWriteFile(hRequest,lpFormElement->lpFormPostfix,lpFormElement->dwFormPostfixSize,&dwWrite))
                        {
                            bFailed=true;
                            break;
                        }
                    }

                    lpFormElement=lpFormElement->lpNext;
                }

                if (bFailed)
                    break;
            }
            else
            {
                DWORD dwWrite=0;
                if (!InternetWriteFile(hRequest,lpReqData->reBinaryElement.lpElementData,lpReqData->reBinaryElement.dwElementSize,&dwWrite))
                    break;
            }

            bRet=(HttpEndRequestA(hRequest,NULL,HSR_INITIATE,NULL) != FALSE);
        }
        while (false);

        return bRet;
    }

    bool InetCompileRequestAndSend(HTTP_REQUEST_HANDLE *lpReq)
    {
        bool bRet=false;
        do
        {
            COMPILED_REQUEST *lpData=NULL;
            if (!CompileRequest(lpReq,&lpData))
                break;

            if (lpData)
            {
                char *lpHdr;
                if (StrFormatExA(&lpHdr,dcrA_e8548ef7("Content-Length: %d\r\n"),lpData->dwCompiledRequestSize))
                {
                    HttpAddRequestHeadersA(lpReq->hReq,lpHdr,-1,HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
                    MemFree(lpHdr);
                }

                bRet=WriteRequestData(lpReq->hReq,lpData);

                FreeRequestData(lpData);
            }
            else
                bRet=(HttpSendRequestA(lpReq->hReq,NULL,0,NULL,0) != FALSE);

            /// удаляем "лишние" заголовки
            HttpAddRequestHeadersA(lpReq->hReq,dcrA_6194aa1c("Content-Length:\r\n"),-1,HTTP_ADDREQ_FLAG_REPLACE);

            if (lpReq->dwDataType != HTTP_DATA_TYPE_UNKNOWN)
            {
                HttpAddRequestHeadersA(lpReq->hReq,dcrA_fd1758e3("Content-Type:\r\n"),-1,HTTP_ADDREQ_FLAG_REPLACE);
                HttpAddRequestHeadersA(lpReq->hReq,dcrA_bb029477("Content-Transfer-Encoding:\r\n"),-1,HTTP_ADDREQ_FLAG_REPLACE);
            }

            if (!bRet)
                break;

            /// очищаем список аргументов
            if (lpReq->dwRequestFlags & INET_REQUEST_FLAG_FREE_ARGS_IF_SENT)
            {
                InetArgsList_Destroy(lpReq->hArgsList);
                lpReq->hArgsList=NULL;
            }
        }
        while (false);

        return bRet;
    }
}


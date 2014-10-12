#include "sys_includes.h"

#include "wsprintf.h"
#include "scanf.h"

#include "syslib\mem.h"
#include "syslib\str.h"
#include "syslib\debug.h"

#include <syslib\strcrypt.h>
#include "str_crx.h"

namespace SYSLIB
{
    static SCANF_TYPE PrepareFormatValue(char cSwitch,SCANF_FORMAT *lpArg,bool bAnsi)
    {
        switch (cSwitch)
        {
            case 'c':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & SCANF_LONG) ? SCT_CHAR : SCT_WCHAR;
                else
                    lpArg->dwType=(lpArg->dwFlags & SCANF_LONG) ? SCT_WCHAR : SCT_CHAR;
                break;
            }
            case 'C':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & SCANF_SHORT) ? SCT_WCHAR : SCT_CHAR;
                else
                    lpArg->dwType=(lpArg->dwFlags & SCANF_SHORT) ? SCT_CHAR : SCT_WCHAR;
                break;
            }
            case 'd':
            case 'i':
            {
                if (!(lpArg->dwFlags & (SCANF_LONG|SCANF_SHORT|SCANF_LONGLONG)))
                    lpArg->dwFlags|=SCANF_LONG;

                lpArg->dwType=SCT_SIGNED;
                break;
            }
            case 's':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & (SCANF_LONG|SCANF_WIDE)) ? SCT_STRINGA : SCT_STRINGW;
                else
                    lpArg->dwType=(lpArg->dwFlags & (SCANF_LONG|SCANF_WIDE)) ? SCT_STRINGW : SCT_STRINGA;
                break;
            }
            case 'S':
            {
                if (!bAnsi)
                    lpArg->dwType=(lpArg->dwFlags & (SCANF_SHORT|SCANF_WIDE)) ? SCT_STRINGW : SCT_STRINGA;
                else
                    lpArg->dwType=(lpArg->dwFlags & (SCANF_SHORT|SCANF_WIDE)) ? SCT_STRINGA : SCT_STRINGW;
                break;
            }
            case 'u':
            {
                if (!(lpArg->dwFlags & (SCANF_LONG|SCANF_SHORT|SCANF_LONGLONG)))
                    lpArg->dwFlags|=SCANF_LONG;

                lpArg->dwType=SCT_UNSIGNED;
                break;
            }
            case 'p':
            case 'P':
            {
                lpArg->dwWidth=sizeof(DWORD_PTR)*2;
                lpArg->dwFlags|=SCANF_PTR;
            }
            case 'X':
            case 'x':
            {
                if (!(lpArg->dwFlags & SCANF_PTR))
                {
                    if (!(lpArg->dwFlags & (SCANF_LONG|SCANF_SHORT|SCANF_LONGLONG)))
                        lpArg->dwFlags|=SCANF_LONG;
                }

                lpArg->dwType=SCT_HEX;
                break;
            }
            case 'o':
            {
                if (!(lpArg->dwFlags & (SCANF_LONG|SCANF_SHORT|SCANF_LONGLONG)))
                    lpArg->dwFlags|=SCANF_LONG;

                lpArg->dwType=SCT_OCT;
                break;
            }
    #ifdef _SCANF_USE_DOUBLE
            case 'e':
            case 'E':
            case 'f':
            case 'g':
            case 'G':
            {
                lpArg->dwType=SCT_DOUBLE;
                break;
            }
    #endif
            case '[':
            {
                lpArg->dwType=SCT_BITMAP;
                break;
            }
            default:
            {
                lpArg->dwType=SCT_UNKNOWN;
                break;
            }
        }
        return lpArg->dwType;
    }

    static DWORD ParseFormatW(LPCWSTR lpFormat,SCANF_FORMAT *lpArg)
    {
        LPCWSTR p=lpFormat;
        memset(lpArg,0,sizeof(*lpArg));

        if (*p == L'*')
        {
            lpArg->dwFlags|=SCANF_SUPPRESS;
            p++;
        }

        lpArg->dwWidth=GetIntParamW(&p);
        if (!lpArg->dwWidth)
            lpArg->dwWidth--;

        if (*p == L'l')
        {
            p++;
            if (*p == L'l')
            {
                p++;
                lpArg->dwFlags|=SCANF_LONGLONG;
            }
            else
                lpArg->dwFlags|=SCANF_LONG;
        }
        else if (*p == L'h')
        {
            lpArg->dwFlags|=SCANF_SHORT;
            p++;
        }
        else if (*p == L'w')
        {
            lpArg->dwFlags|=SCANF_WIDE;
            p++;
        }
        else if (*p == L'L')
        {
            lpArg->dwFlags|=SCANF_LONGLONG;
            p++;
        }
        else if (*p == L'I')
        {
            if ((p[1] == L'6') && (p[2] == L'4'))
            {
                lpArg->dwFlags&=~SCANF_INT32;
                lpArg->dwFlags|=SCANF_INT64;
                p+=3;
            }
            else if ((p[1] == L'3') && (p[2] == L'2'))
            {
                lpArg->dwFlags&=~SCANF_INT64;
                lpArg->dwFlags|=SCANF_INT32;
                p+=3;
            }
            else
            {
                lpArg->dwFlags&=~(SCANF_INT32|SCANF_INT64);
                lpArg->dwFlags|=SCANF_PTR;
                p++;
            }
        }

        if (PrepareFormatValue((char)*p,lpArg,false) == SCT_UNKNOWN)
            p=lpFormat-1;
        else if (lpArg->dwType == SCT_BITMAP)
        {
            WCHAR *lpTable=lpArg->bitmap.lpBitsMapW=(WCHAR*)MemAlloc(UNICODE_TABLESIZE);

            p++;
            if (*p == L'^')
            {
                p++;
                lpArg->bitmap.bInvert=true;
            }

            WCHAR wPrevChar=0;
            if (*p == L']')
            {
                wPrevChar=L']';
                p++;
                SCANF_SET_TBL_BIT(L']');
            }

            while ((*p) && (*p != L']'))
            {
                WCHAR wCurChar=*p++;
                if ((wCurChar != L'-') || (!wPrevChar) || (*p == L']'))
                {
                    wPrevChar=wCurChar;
                    SCANF_SET_TBL_BIT(wCurChar);
                }
                else
                {
                    wCurChar=*p++;

                    WCHAR wLast;
                    if (wPrevChar < wCurChar)
                        wLast=wCurChar;
                    else
                    {
                        wLast=wPrevChar;
                        wPrevChar=wCurChar;
                    }

                    for (WCHAR wChr=wPrevChar; wChr < wLast; wChr++)
                        SCANF_SET_TBL_BIT(wChr);

                    SCANF_SET_TBL_BIT(wLast);
                    wPrevChar=0;
                }
            }
        }

        return (p-lpFormat)+1;
    }

    static int CharToDigitW(WCHAR wChr,DWORD dwBase)
    {
        int dwDigit=-1;

        if ((wChr >= L'0') && (wChr <= L'9') && (wChr <= L'0'+dwBase-1))
            dwDigit=(wChr-L'0');
        else if (dwBase > 10)
        {
            if ((wChr >= L'A') && (wChr <= L'Z') && (wChr <= L'A'+dwBase-11))
                dwDigit=(wChr-L'A'+10);

            if ((wChr >= L'a') && (wChr <= L'z') && (wChr <= L'a'+dwBase-11))
                dwDigit=(wChr-L'a'+10);
        }
        return dwDigit;
    }

    static DWORD CopyArgumentW(LPCWSTR lpSource,SCANF_FORMAT *lpFormat,SCANF_DATA sdArg,DWORD *lpResult)
    {
        DWORD dwLen=0;

        bool bDone=false;
        while ((*lpSource) && (iswspace(*lpSource)))
        {
            lpSource++;
            dwLen++;
        }

        if (*lpSource)
        {
            DWORD dwBase=0;
            switch (lpFormat->dwType)
            {
                case SCT_CHAR:
                {
                    if (sdArg.lpChr)
                        *sdArg.lpChr=(char)*lpSource;

                    dwLen=1;
                    bDone=true;
                    break;
                }
                case SCT_WCHAR:
                {
                    if (sdArg.lpWChr)
                        *sdArg.lpWChr=*lpSource;

                    dwLen=1;
                    bDone=true;
                    break;
                }
                case SCT_STRINGA:
                {
                    DWORD dwStrLen=0;
                    for (; lpFormat->dwWidth; dwStrLen++, lpSource++)
                    {
                        if ((!*lpSource) || (iswspace(*lpSource)))
                            break;

                        if (sdArg.lpStrA)
                            StrUnicodeToAnsi(lpSource,1,&sdArg.lpStrA[dwStrLen],1);

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (sdArg.lpStrA)
                        sdArg.lpStrA[dwStrLen]=0;

                    dwLen+=dwStrLen;
                    if (dwStrLen)
                        bDone=true;
                    break;
                }
                case SCT_STRINGW:
                {
                    DWORD dwStrLen=0;
                    for (; lpFormat->dwWidth; dwStrLen++, lpSource++)
                    {
                        if ((!*lpSource) || (iswspace(*lpSource)))
                            break;

                        if (sdArg.lpStrW)
                            sdArg.lpStrW[dwStrLen]=*lpSource;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (sdArg.lpStrW)
                        sdArg.lpStrW[dwStrLen]=0;

                    dwLen+=dwStrLen;
                    if (dwStrLen)
                        bDone=true;
                    break;
                }
                case SCT_OCT:
                {
                    dwBase=8;
                    goto number;
                }
                case SCT_HEX:
                {
                    dwBase=16;
                    goto number;
                }
                case SCT_SIGNED:
                case SCT_UNSIGNED:
                {
    number:
                    unsigned __int64 uNumber=0;
                    bool bNegative=false,
                         bGoodNumber=true;

                    if ((*lpSource == L'-') || (*lpSource == L'+'))
                    {
                        bNegative=(*lpSource == L'-');

                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if ((lpFormat->dwWidth) && (*lpSource == L'0'))
                    {
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        if ((lpFormat->dwWidth) && ((*lpSource == L'x') || (*lpSource == L'X')))
                        {
                            if (!dwBase)
                                dwBase=16;

                            if (dwBase == 16)
                            {
                                lpSource++;
                                dwLen++;

                                if (lpFormat->dwWidth > 0)
                                    lpFormat->dwWidth--;
                            }
                            else
                                bGoodNumber=false;
                        }
                        else if (!dwBase)
                            dwBase=8;
                    }

                    if (!dwBase)
                        dwBase=10;

                    while ((lpFormat->dwWidth) && (*lpSource == L'0'))
                    {
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitW(*lpSource,dwBase) != -1))
                    {
                        uNumber=uNumber*dwBase+CharToDigitW(*lpSource,dwBase);
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (!bGoodNumber)
                        break;

                    if (sdArg.lpInt)
                    {
                        if (bNegative)
                        {
                            if (lpFormat->dwType == SCT_SIGNED)
                                uNumber=(unsigned __int64 )(-(__int64)uNumber);
                        }

                        if (lpFormat->dwFlags & SCANF_INT32)
                        {
                            PLONG32 lpInt32=(PLONG32)sdArg.lpInt;
                            *lpInt32=(LONG32)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_SHORT)
                        {
                            PSHORT lpShort=(PSHORT)sdArg.lpInt;
                            *lpShort=(SHORT)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_LONG)
                        {
                            PLONG lpShort=(PLONG)sdArg.lpInt;
                            *lpShort=(LONG)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_PTR)
                        {
                            LPVOID *lpShort=(LPVOID *)sdArg.lpInt;
                            *lpShort=(LPVOID)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_INT64)
                            *sdArg.lpInt=uNumber;
                    }

                    bDone=true;
                    break;
                }
    #ifdef _SCANF_USE_DOUBLE
                case SCT_DOUBLE:
                {
                    long double ldDouble=0;
                    bool bNegative=0;

                    if ((*lpSource == L'-') || (*lpSource == L'+'))
                    {
                        bNegative=(*lpSource == L'-');

                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (*lpSource != L'.')
                    {
                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitW(*lpSource,10)))
                        {
                            ldDouble=ldDouble*10+(*lpSource-L'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }
                    }

                    if ((lpFormat->dwWidth) && (*lpSource == L'.'))
                    {
                        long double ldDec=1;

                        lpSource++;
                        dwLen--;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitW(*lpSource,10)))
                        {
                            ldDec/=10;
                            ldDouble+=ldDec*(*lpSource-L'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }
                    }

                    if ((lpFormat->dwWidth) && ((*lpSource == L'e') || (*lpSource == L'E')))
                    {
                        int iExp=0;
                        bool bNegExp=false;
                        float fExp;

                        lpSource++;
                        dwLen--;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        if ((lpFormat->dwWidth) && ((*lpSource == L'-') || (*lpSource == L'+')))
                        {
                            bNegExp=(*lpSource == L'-');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }

                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitW(*lpSource,10)))
                        {
                            iExp*=10;
                            iExp+=(*lpSource-L'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }

                        fExp=(bNegExp) ? 0.1f : 10.0f;
                        while (iExp != 0)
                        {
                            if (iExp & 1)
                                ldDouble*=fExp;
                            iExp/=2;
                            fExp=fExp*fExp;
                        }
                    }

                    if (sdArg.lpLongDouble)
                    {
                        if (lpFormat->dwFlags & SCANF_LONGLONG)
                            *sdArg.lpLongDouble=ldDouble;
                        else if (lpFormat->dwFlags & SCANF_LONG)
                        {
                            double *dDouble=(double*)sdArg.lpLongDouble;
                            *dDouble=(double)ldDouble;
                        }
                        else
                        {
                            float *fFloat=(float*)sdArg.lpLongDouble;
                            *fFloat=(double)ldDouble;
                        }
                    }
                    bDone=true;
                    break;
                }
    #endif
                case SCT_BITMAP:
                {
                    if (!lpFormat->bitmap.lpBitsMapW)
                        break;

                    WCHAR *lpTable=lpFormat->bitmap.lpBitsMapW,
                          *lpOut=sdArg.lpStrW;

                    DWORD dwCharsCount=0,
                          dwInverted=(lpFormat->bitmap.bInvert != false);
                    while ((lpFormat->dwWidth) && (*lpSource))
                    {
                        WCHAR wChr=*lpSource++;
                        DWORD dwIsBitSet=(SCANF_IS_TBL_BIT_SET(wChr) != 0);
                        if (dwIsBitSet == dwInverted)
                            break;

                        *lpOut++=wChr;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        dwCharsCount++;
                    }

                    if (lpOut)
                        *lpOut=0;

                    MemFree(lpTable);
                    bDone=(dwCharsCount != 0);
                    break;
                }
            }
        }

        if (bDone)
            *lpResult=1;
        return dwLen;
    }

    DWORD StrFmt_ScanStringW(LPCWSTR lpString,LPCWSTR lpFormat,va_list args)
    {
        if ((!lpFormat) || (!lpString) || (!lpString[0]))
            return 0;

        DWORD dwArguments=0;

        LPCWSTR lpFmtPtr=lpFormat,
                lpStrPtr=lpString;

        while (*lpFmtPtr)
        {
            if (iswspace(*lpFmtPtr))
            {
                while ((*lpStrPtr) && (iswspace(*lpStrPtr)))
                    lpStrPtr++;

                lpFmtPtr++;
            }

            if (*lpFmtPtr == L'%')
            {
                lpFmtPtr++;

                SCANF_FORMAT scfFormat;
                lpFmtPtr+=ParseFormatW(lpFmtPtr,&scfFormat);

                DWORD dwBase=0;
                bool bNegative=false,
                     bGoodDigit=true;

                SCANF_DATA scfArgData={0};
                if (!(scfFormat.dwFlags & SCANF_SUPPRESS))
                {
                    switch (scfFormat.dwType)
                    {
                        case SCT_OCT:
                        case SCT_HEX:
                        case SCT_SIGNED:
                        case SCT_UNSIGNED:
                        {
                            scfArgData.lpInt=va_arg(args,PLONGLONG);
                            break;
                        }
    #ifdef _SCANF_USE_DOUBLE
                        case SCT_DOUBLE:
                        {
                            scfArgData.lpLongDouble=va_arg(args,long double *);
                            break;
                        }
    #endif
                        case SCT_WCHAR:
                        {
                            scfArgData.lpWChr=va_arg(args,PWCHAR);
                            break;
                        }
                        case SCT_CHAR:
                        {
                            scfArgData.lpChr=va_arg(args,PCHAR);
                            break;
                        }
                        case SCT_STRINGA:
                        {
                            scfArgData.lpStrA=va_arg(args,LPSTR);
                            break;
                        }
                        case SCT_BITMAP:
                        case SCT_STRINGW:
                        {
                            scfArgData.lpStrW=va_arg(args,LPWSTR);
                            break;
                        }
                    }
                }

                DWORD dwRes=0,
                      dwLen=CopyArgumentW(lpStrPtr,&scfFormat,scfArgData,&dwRes);
                if (!dwRes)
                    break;

                dwArguments+=dwRes;
                lpStrPtr+=dwLen;
            }
            else
            {
                if (*lpFmtPtr == *lpStrPtr)
                {
                    lpFmtPtr++;
                    lpStrPtr++;
                }
                else
                    break;
            }
        }

        return dwArguments;
    }

    static DWORD ParseFormatA(LPCSTR lpFormat,SCANF_FORMAT *lpArg)
    {
        LPCSTR p=lpFormat;
        memset(lpArg,0,sizeof(*lpArg));

        if (*p == '*')
        {
            lpArg->dwFlags|=SCANF_SUPPRESS;
            p++;
        }

        lpArg->dwWidth=GetIntParamA(&p);
        if (!lpArg->dwWidth)
            lpArg->dwWidth--;

        if (*p == 'l')
        {
            p++;
            if (*p == 'l')
            {
                p++;
                lpArg->dwFlags|=SCANF_LONGLONG;
            }
            else
                lpArg->dwFlags|=SCANF_LONG;
        }
        else if (*p == 'h')
        {
            lpArg->dwFlags|=SCANF_SHORT;
            p++;
        }
        else if (*p == 'w')
        {
            lpArg->dwFlags|=SCANF_WIDE;
            p++;
        }
        else if (*p == 'L')
        {
            lpArg->dwFlags|=SCANF_LONGLONG;
            p++;
        }
        else if (*p == 'I')
        {
            if ((p[1] == '6') && (p[2] == '4'))
            {
                lpArg->dwFlags&=~SCANF_INT32;
                lpArg->dwFlags|=SCANF_INT64;
                p+=3;
            }
            else if ((p[1] == '3') && (p[2] == '2'))
            {
                lpArg->dwFlags&=~SCANF_INT64;
                lpArg->dwFlags|=SCANF_INT32;
                p+=3;
            }
            else
            {
                lpArg->dwFlags&=~(SCANF_INT32|SCANF_INT64);
                lpArg->dwFlags|=SCANF_PTR;
                p++;
            }
        }

        if (PrepareFormatValue(*p,lpArg,true) == SCT_UNKNOWN)
            p=lpFormat-1;
        else if (lpArg->dwType == SCT_BITMAP)
        {
            char *lpTable=lpArg->bitmap.lpBitsMapA=(char*)MemAlloc(ANSI_TABLESIZE);

            p++;
            if (*p == '^')
            {
                p++;
                lpArg->bitmap.bInvert=true;
            }

            char cPrevChar=0;
            if (*p == ']')
            {
                cPrevChar=']';
                p++;
                SCANF_SET_TBL_BIT(']');
            }

            while ((*p) && (*p != ']'))
            {
                char cCurChar=*p++;
                if ((cCurChar != '-') || (!cPrevChar) || (*p == ']'))
                {
                    cPrevChar=cCurChar;
                    SCANF_SET_TBL_BIT(cCurChar);
                }
                else
                {
                    cCurChar=*p++;

                    char cLast;
                    if (cPrevChar < cCurChar)
                        cLast=cCurChar;
                    else
                    {
                        cLast=cPrevChar;
                        cPrevChar=cCurChar;
                    }

                    for (char cChr=cPrevChar; cChr < cLast; cChr++)
                        SCANF_SET_TBL_BIT(cChr);

                    SCANF_SET_TBL_BIT(cLast);
                    cPrevChar=0;
                }
            }
        }

        return (p-lpFormat)+1;
    }

    static int CharToDigitA(char cChr,DWORD dwBase)
    {
        int dwDigit=-1;

        if ((cChr >= '0') && (cChr <= '9') && (cChr <= '0'+dwBase-1))
            dwDigit=(cChr-'0');
        else if (dwBase > 10)
        {
            if ((cChr >= 'A') && (cChr <= 'Z') && (cChr <= 'A'+dwBase-11))
                dwDigit=(cChr-'A'+10);

            if ((cChr >= 'a') && (cChr <= 'z') && (cChr <= 'a'+dwBase-11))
                dwDigit=(cChr-'a'+10);
        }
        return dwDigit;
    }

    static DWORD CopyArgumentA(LPCSTR lpSource,SCANF_FORMAT *lpFormat,SCANF_DATA sdArg,DWORD *lpResult)
    {
        DWORD dwLen=0;

        bool bDone=false;
        while ((*lpSource) && (isspace(*lpSource)))
        {
            lpSource++;
            dwLen++;
        }

        if (*lpSource)
        {
            DWORD dwBase=0;
            switch (lpFormat->dwType)
            {
                case SCT_CHAR:
                {
                    if (sdArg.lpChr)
                        *sdArg.lpChr=(char)*lpSource;

                    dwLen=1;
                    bDone=true;
                    break;
                }
                case SCT_WCHAR:
                {
                    if (sdArg.lpWChr)
                        *sdArg.lpWChr=(WCHAR)*lpSource;

                    dwLen=1;
                    bDone=true;
                    break;
                }
                case SCT_STRINGA:
                {
                    DWORD dwStrLen=0;
                    for (; lpFormat->dwWidth; dwStrLen++, lpSource++)
                    {
                        if ((!*lpSource) || (isspace(*lpSource)))
                            break;

                        if (sdArg.lpStrA)
                            sdArg.lpStrA[dwStrLen]=*lpSource;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (sdArg.lpStrA)
                        sdArg.lpStrA[dwStrLen]=0;

                    dwLen+=dwStrLen;
                    if (dwStrLen)
                        bDone=true;
                    break;
                }
                case SCT_STRINGW:
                {
                    DWORD dwStrLen=0;
                    for (; lpFormat->dwWidth; dwStrLen++, lpSource++)
                    {
                        if ((!*lpSource) || (isspace(*lpSource)))
                            break;

                        if (sdArg.lpStrW)
                            StrAnsiToUnicode(lpSource,1,&sdArg.lpStrW[dwStrLen],1);

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (sdArg.lpStrW)
                        sdArg.lpStrW[dwStrLen]=0;

                    dwLen+=dwStrLen;
                    if (dwStrLen)
                        bDone=true;
                    break;
                }
                case SCT_OCT:
                {
                    dwBase=8;
                    goto number;
                }
                case SCT_HEX:
                {
                    dwBase=16;
                    goto number;
                }
                case SCT_SIGNED:
                case SCT_UNSIGNED:
                {
    number:
                    unsigned __int64 uNumber=0;
                    bool bNegative=false,
                         bGoodNumber=true;

                    if ((*lpSource == '-') || (*lpSource == '+'))
                    {
                        bNegative=(*lpSource == '-');

                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if ((lpFormat->dwWidth) && (*lpSource == '0'))
                    {
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        if ((lpFormat->dwWidth) && ((*lpSource == 'x') || (*lpSource == 'X')))
                        {
                            if (!dwBase)
                                dwBase=16;

                            if (dwBase == 16)
                            {
                                lpSource++;
                                dwLen++;

                                if (lpFormat->dwWidth > 0)
                                    lpFormat->dwWidth--;
                            }
                            else
                                bGoodNumber=false;
                        }
                        else if (!dwBase)
                            dwBase=8;
                    }

                    if (!dwBase)
                        dwBase=10;

                    while ((lpFormat->dwWidth) && (*lpSource == '0'))
                    {
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitA(*lpSource,dwBase) != -1))
                    {
                        uNumber=uNumber*dwBase+CharToDigitA(*lpSource,dwBase);
                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (!bGoodNumber)
                        break;

                    if (sdArg.lpInt)
                    {
                        if (bNegative)
                        {
                            if (lpFormat->dwType == SCT_SIGNED)
                                uNumber=(unsigned __int64 )(-(__int64)uNumber);
                        }

                        if (lpFormat->dwFlags & SCANF_INT32)
                        {
                            PLONG32 lpInt32=(PLONG32)sdArg.lpInt;
                            *lpInt32=(LONG32)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_SHORT)
                        {
                            PSHORT lpShort=(PSHORT)sdArg.lpInt;
                            *lpShort=(SHORT)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_LONG)
                        {
                            PLONG lpShort=(PLONG)sdArg.lpInt;
                            *lpShort=(LONG)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_PTR)
                        {
                            LPVOID *lpShort=(LPVOID *)sdArg.lpInt;
                            *lpShort=(LPVOID)uNumber;
                        }
                        else if (lpFormat->dwFlags & SCANF_INT64)
                            *sdArg.lpInt=uNumber;
                    }

                    bDone=true;
                    break;
                }
    #ifdef _SCANF_USE_DOUBLE
                case SCT_DOUBLE:
                {
                    long double ldDouble=0;
                    bool bNegative=0;

                    if ((*lpSource == '-') || (*lpSource == '+'))
                    {
                        bNegative=(*lpSource == '-');

                        lpSource++;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;
                    }

                    if (*lpSource != '.')
                    {
                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitA(*lpSource,10)))
                        {
                            ldDouble=ldDouble*10+(*lpSource-'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }
                    }

                    if ((lpFormat->dwWidth) && (*lpSource == '.'))
                    {
                        long double ldDec=1;

                        lpSource++;
                        dwLen--;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitA(*lpSource,10)))
                        {
                            ldDec/=10;
                            ldDouble+=ldDec*(*lpSource-'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }
                    }

                    if ((lpFormat->dwWidth) && ((*lpSource == 'e') || (*lpSource == 'E')))
                    {
                        int iExp=0;
                        bool bNegExp=false;
                        float fExp;

                        lpSource++;
                        dwLen--;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        if ((lpFormat->dwWidth) && ((*lpSource == '-') || (*lpSource == '+')))
                        {
                            bNegExp=(*lpSource == '-');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }

                        while ((lpFormat->dwWidth) && (*lpSource) && (CharToDigitA(*lpSource,10)))
                        {
                            iExp*=10;
                            iExp+=(*lpSource-'0');

                            lpSource++;
                            dwLen--;

                            if (lpFormat->dwWidth > 0)
                                lpFormat->dwWidth--;
                        }

                        fExp=(bNegExp) ? 0.1f : 10.0f;
                        while (iExp != 0)
                        {
                            if (iExp & 1)
                                ldDouble*=fExp;
                            iExp/=2;
                            fExp=fExp*fExp;
                        }
                    }

                    if (sdArg.lpLongDouble)
                    {
                        if (lpFormat->dwFlags & SCANF_LONGLONG)
                            *sdArg.lpLongDouble=ldDouble;
                        else if (lpFormat->dwFlags & SCANF_LONG)
                        {
                            double *dDouble=(double*)sdArg.lpLongDouble;
                            *dDouble=(double)ldDouble;
                        }
                        else
                        {
                            float *fFloat=(float*)sdArg.lpLongDouble;
                            *fFloat=(double)ldDouble;
                        }
                    }
                    bDone=true;
                    break;
                }
    #endif
                case SCT_BITMAP:
                {
                    if (!lpFormat->bitmap.lpBitsMapA)
                        break;

                    char *lpTable=lpFormat->bitmap.lpBitsMapA,
                         *lpOut=sdArg.lpStrA;

                    DWORD dwCharsCount=0,
                          dwInverted=(lpFormat->bitmap.bInvert != false);
                    while ((lpFormat->dwWidth) && (*lpSource))
                    {
                        char cChr=*lpSource++;
                        DWORD dwIsBitSet=(SCANF_IS_TBL_BIT_SET(cChr) != 0);
                        if (dwIsBitSet == dwInverted)
                            break;

                        *lpOut++=cChr;
                        dwLen++;

                        if (lpFormat->dwWidth > 0)
                            lpFormat->dwWidth--;

                        dwCharsCount++;
                    }

                    if (lpOut)
                        *lpOut=0;

                    MemFree(lpTable);
                    bDone=(dwCharsCount != 0);
                    break;
                }
            }
        }

        if (bDone)
            *lpResult=1;
        return dwLen;
    }

    DWORD StrFmt_ScanStringA(LPCSTR lpString,LPCSTR lpFormat,va_list args)
    {
        if ((!lpFormat) || (!lpString) || (!lpString[0]))
            return 0;

        DWORD dwArguments=0;

        LPCSTR lpFmtPtr=lpFormat,
               lpStrPtr=lpString;

        while (*lpFmtPtr)
        {
            if (isspace(*lpFmtPtr))
            {
                while ((*lpStrPtr) && (isspace(*lpStrPtr)))
                    lpStrPtr++;

                lpFmtPtr++;
            }

            if (*lpFmtPtr == '%')
            {
                lpFmtPtr++;

                SCANF_FORMAT scfFormat;
                lpFmtPtr+=ParseFormatA(lpFmtPtr,&scfFormat);

                DWORD dwBase=0;
                bool bNegative=false,
                     bGoodDigit=true;

                SCANF_DATA scfArgData={0};
                if (!(scfFormat.dwFlags & SCANF_SUPPRESS))
                {
                    switch (scfFormat.dwType)
                    {
                        case SCT_OCT:
                        case SCT_HEX:
                        case SCT_SIGNED:
                        case SCT_UNSIGNED:
                        {
                            scfArgData.lpInt=va_arg(args,PLONGLONG);
                            break;
                        }
    #ifdef _SCANF_USE_DOUBLE
                        case SCT_DOUBLE:
                        {
                            scfArgData.lpLongDouble=va_arg(args,long double *);
                            break;
                        }
    #endif
                        case SCT_WCHAR:
                        {
                            scfArgData.lpWChr=va_arg(args,PWCHAR);
                            break;
                        }
                        case SCT_CHAR:
                        {
                            scfArgData.lpChr=va_arg(args,PCHAR);
                            break;
                        }
                        case SCT_STRINGA:
                        {
                            scfArgData.lpStrA=va_arg(args,LPSTR);
                            break;
                        }
                        case SCT_BITMAP:
                        case SCT_STRINGW:
                        {
                            scfArgData.lpStrW=va_arg(args,LPWSTR);
                            break;
                        }
                    }
                }

                DWORD dwRes=0,
                      dwLen=CopyArgumentA(lpStrPtr,&scfFormat,scfArgData,&dwRes);
                if (!dwRes)
                    break;

                dwArguments+=dwRes;
                lpStrPtr+=dwLen;
            }
            else
            {
                if (*lpFmtPtr == *lpStrPtr)
                {
                    lpFmtPtr++;
                    lpStrPtr++;
                }
                else
                    break;
            }
        }

        return dwArguments;
    }
}

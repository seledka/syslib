#ifndef STRFMT_H_INCLUDED
#define STRFMT_H_INCLUDED

#define MAX_FORMAT_STRING_EX_BUFF_SIZE 10*1024*1024

namespace SYSLIB
{
    DWORD wsprintfExW(LPWSTR *lppBuffer,DWORD dwOffset,LPCWSTR lpFormat,va_list args);
    DWORD wsprintfExA(LPSTR *lppBuffer,DWORD dwOffset,LPCSTR lpFormat,va_list args);
};

#endif // STRFMT_H_INCLUDED

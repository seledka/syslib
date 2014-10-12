#ifndef REGARGS_H_INCLUDED
#define REGARGS_H_INCLUDED

namespace SYSLIB
{
    bool InetCompileRequestAndSend(HTTP_REQUEST_HANDLE *lpReq);
};

struct REQUEST_ELEMENT
{
    DWORD dwElementSize;
    void *lpElementData;
};

struct FORM_DATA
{
    char *lpFormPrefix;
    DWORD dwFormPrefixSize;

    REQUEST_ELEMENT feFormElement;

    char *lpFormPostfix;
    DWORD dwFormPostfixSize;

    FORM_DATA *lpNext;
};

struct COMPILED_REQUEST
{
    DWORD dwCompiledRequestSize;
    bool bFormData;
    union
    {
        REQUEST_ELEMENT reBinaryElement;
        FORM_DATA fdFormElements;
    };
};

#endif // REGARGS_H_INCLUDED

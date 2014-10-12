#include "sys_includes.h"

#include "rc4.h"
#include "syslib\mem.h"

static void rc4Init(const void *binKey, WORD binKeySize, RC4KEY *key)
{
    register BYTE swapByte;
    register BYTE index1 = 0, index2 = 0;
    LPBYTE state = &key->state[0];
    register WORD i;

    key->x = 0;
    key->y = 0;

    for(i = 0; i < 256; i++)state[i] = i;
    for(i = 0; i < 256; i++)
    {
        index2 = (((LPBYTE)binKey)[index1] + state[i] + index2) & 0xFF;
        swap_byte(state[i], state[index2]);
        if(++index1 == binKeySize)index1 = 0;
    }
    return;
}

static void rc4(const void *in,void *out, DWORD size, RC4KEY *key)
{

    register BYTE swapByte;
    register BYTE x = key->x;
    register BYTE y = key->y;
    LPBYTE state = &key->state[0];

    for(register DWORD i = 0; i < size; i++)
    {
        x = (x + 1) & 0xFF;
        y = (state[x] + y) & 0xFF;
        swap_byte(state[x], state[y]);
        ((LPBYTE)out)[i] = ((LPBYTE)in)[i] ^ (state[(state[x] + state[y]) & 0xFF]);
    }

    key->x = x;
    key->y = y;
    return;
}

SYSLIBFUNC(void) rc4Full(const LPVOID binKey,WORD binKeySize,const LPVOID buffer,DWORD size,LPVOID out)
{
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(binKey,binKeySize))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(buffer,size))
            break;

        if (!out)
            out=(LPVOID)buffer;

        if (!SYSLIB_SAFE::CheckParamWrite(out,size))
            break;

        RC4KEY key;
        rc4Init(binKey,binKeySize,&key);
        rc4(buffer,out,size,&key);
    }
    while (false);
    return;
}

SYSLIBFUNC(LPBYTE) rc4FullEx(const LPVOID binKey,WORD binKeySize,const LPVOID buffer,DWORD size)
{
    LPBYTE lpOut=NULL;
    do
    {
        if (!SYSLIB_SAFE::CheckParamRead(binKey,binKeySize))
            break;

        if (!SYSLIB_SAFE::CheckParamRead(buffer,size))
            break;

        lpOut=(LPBYTE)MemQuickAlloc(size);

        if (!lpOut)
            break;

        rc4Full(binKey,binKeySize,buffer,size,lpOut);
    }
    while (false);
    return lpOut;
}


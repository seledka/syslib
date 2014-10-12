#ifndef ARUN_H_INCLUDED
#define ARUN_H_INCLUDED

#include "arun_prot.h"

struct ARUN_PARAM
{
    DWORD dwRet;
    LPCWSTR lpFile;
    PROTECTED_ITEMS_HIVE *lpHive;
};

#endif // ARUN_H_INCLUDED

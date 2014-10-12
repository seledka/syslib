#ifndef ARUN_PROT_H_INCLUDED
#define ARUN_PROT_H_INCLUDED

#include "syslib\criticalsections.h"

enum PROTECTED_ITEM_TYPE
{
    PROTECTED_LNK=1,
    PROTECTED_REG
};

struct PROTECTED_ITEM
{
    PROTECTED_ITEM_TYPE dwType;
    union
    {
        WCHAR szArunDir[MAX_PATH];
        WCHAR szRootKey[MAX_PATH];
    };
    union
    {
        WCHAR szLnkName[150];
        WCHAR szValueName[150];
    };
    PROTECTED_ITEM *lpNext;
};

struct PROTECTED_ITEMS_HIVE
{
    WCHAR szProtectedFile[MAX_PATH];
    SAFE_CRITICAL_SECTION csProtection;
    HANDLE hStopEvent;
    HANDLE hThreadsGroup;
    PROTECTED_ITEM *lpRegItems;
    PROTECTED_ITEM *lpLnkItems;
};

struct PROTECTED_HIVES
{
    PROTECTED_ITEMS_HIVE *lpHive;
    PROTECTED_HIVES *lpNext;
};

namespace SYSLIB
{
    bool Arun_AddProtectedItem(PROTECTED_ITEMS_HIVE *lpHive,PROTECTED_ITEM_TYPE dwType,LPCWSTR lpDir,LPCWSTR lpName);
};

#define LNK_WATCHER_FLAGS FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE
#define REG_WATCHER_FLAGS REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET

#endif // ARUN_PROT_H_INCLUDED

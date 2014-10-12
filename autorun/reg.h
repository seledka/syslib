#ifndef REG_H_INCLUDED
#define REG_H_INCLUDED

#include "arun_prot.h"

namespace SYSLIB
{
    bool ArunReg_CheckStartupW(LPCWSTR lpFile);
    bool ArunReg_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid);
    bool ArunReg_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid);
    bool ArunReg_AppendFileToAllUsersW(LPCWSTR lpFile);
    bool ArunReg_RemoveW(LPCWSTR lpFile);

    bool ArunReg_ProtectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive);
    void ArunReg_UnprotectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive);
};

struct ARUN_REG_KEY
{
    LPCWSTR lpKey;
    LPCWSTR lpValue;
};

#endif // REG_H_INCLUDED

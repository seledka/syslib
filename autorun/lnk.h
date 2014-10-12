#ifndef LNK_H_INCLUDED
#define LNK_H_INCLUDED

#include "syslib\syslib_exp.h"
#include "arun_prot.h"

namespace SYSLIB
{
    bool ArunLnk_CheckStartupW(LPCWSTR lpFile);
    bool ArunLnk_CheckUserStartupW(LPCWSTR lpFile,PSID lpSid);
    bool ArunLnk_AppendFileToUserW(LPCWSTR lpFile,PSID lpSid);
    bool ArunLnk_AppendFileToAllUsersW(LPCWSTR lpFile);
    bool ArunLnk_RemoveW(LPCWSTR lpFile);

    bool ArunLnk_ProtectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive);
    void ArunLnk_UnprotectW(LPCWSTR lpFile,PROTECTED_ITEMS_HIVE *lpHive);

    bool ArunLnk_AppendFileToArunDirInt(LPCWSTR lpFile,LPCWSTR lpDir);
};

#endif // LNK_H_INCLUDED

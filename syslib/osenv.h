#ifndef SYSLIB_OSENV_H_INCLUDED
#define SYSLIB_OSENV_H_INCLUDED

#include "syslib_exp.h"

SYSLIBEXP(BOOL) GetUserFolderPostfixA(int nFolder,LPSTR lpBuffer);
SYSLIBEXP(BOOL) GetUserFolderPostfixW(int nFolder,LPWSTR lpBuffer);

#ifdef UNICODE
#define GetUserFolderPostfix GetUserFolderPostfixW
#else
#define GetUserFolderPostfix GetUserFolderPostfixA
#endif


SYSLIBEXP(void) GetUserDirW(LPWSTR lpOut);
SYSLIBEXP(void) GetUserDirA(LPSTR lpOut);

#ifdef UNICODE
#define GetUserDir GetUserDirW
#else
#define GetUserDir GetUserDirA
#endif


typedef ULONG WINAPI ENUMUSERPROFILEDIRSCALLBACKPARAMA(LPCSTR lpUserProfilePath,LPVOID lpParam);
typedef ULONG WINAPI ENUMUSERPROFILEDIRSCALLBACKPARAMW(LPCWSTR lpUserProfilePath,LPVOID lpParam);

SYSLIBEXP(void) EnumUserProfileDirsParamW(ENUMUSERPROFILEDIRSCALLBACKPARAMW *lpCallback,LPVOID lpParam);
SYSLIBEXP(void) EnumUserProfileDirsParamA(ENUMUSERPROFILEDIRSCALLBACKPARAMA *lpCallback,LPVOID lpParam);

#ifdef UNICODE
#define EnumUserProfileDirsParam EnumUserProfileDirsParamW
#define ENUMUSERPROFILEDIRSCALLBACKPARAM ENUMUSERPROFILEDIRSCALLBACKPARAMW
#else
#define EnumUserProfileDirsParam EnumUserProfileDirsParamA
#define ENUMUSERPROFILEDIRSCALLBACKPARAM ENUMUSERPROFILEDIRSCALLBACKPARAMA
#endif


typedef ULONG WINAPI ENUMUSERPROFILEDIRSCALLBACKA(LPCSTR lpUserProfilePath);
typedef ULONG WINAPI ENUMUSERPROFILEDIRSCALLBACKW(LPCWSTR lpUserProfilePath);

SYSLIBEXP(void) EnumUserProfileDirsW(ENUMUSERPROFILEDIRSCALLBACKW *lpCallback);
SYSLIBEXP(void) EnumUserProfileDirsA(ENUMUSERPROFILEDIRSCALLBACKA *lpCallback);

#ifdef UNICODE
#define EnumUserProfileDirs EnumUserProfileDirsW
#define ENUMUSERPROFILEDIRSCALLBACK ENUMUSERPROFILEDIRSCALLBACKW
#else
#define EnumUserProfileDirs EnumUserProfileDirsA
#define ENUMUSERPROFILEDIRSCALLBACK ENUMUSERPROFILEDIRSCALLBACKA
#endif


SYSLIBEXP(BOOL) GetUserProfileDirectoryBySidW(PSID lpSid,LPWSTR lpBuffer);
SYSLIBEXP(BOOL) GetUserProfileDirectoryBySidA(PSID lpSid,LPSTR lpBuffer);

#ifdef UNICODE
#define GetUserProfileDirectoryhBySid GetUserProfileDirectoryhBySidW
#else
#define GetUserProfileDirectoryhBySid GetUserProfileDirectoryhBySidA
#endif


SYSLIBEXP(BOOL) GetUserStartupDirectoryBySidW(PSID lpSid,LPWSTR lpBuffer);
SYSLIBEXP(BOOL) GetUserStartupDirectoryBySidA(PSID lpSid,LPSTR lpBuffer);

#ifdef UNICODE
#define GetUserStartupDirectoryBySid GetUserStartupDirectoryBySidW
#else
#define GetUserStartupDirectoryBySid GetUserStartupDirectoryBySidA
#endif


typedef ULONG WINAPI ENUMUSERPROFILESCALLBACK(PSID lpSid);
SYSLIBEXP(void) EnumUserProfiles(ENUMUSERPROFILESCALLBACK *lpCallback);

typedef ULONG WINAPI ENUMUSERPROFILESCALLBACKPARAM(PSID lpSid,LPVOID lpParam);
SYSLIBEXP(void) EnumUserProfilesParam(ENUMUSERPROFILESCALLBACKPARAM *lpCallback,LPVOID lpParam);

SYSLIBEXP(BOOL) SysGetCurrentUserSID(PSID *lppSid);

SYSLIBEXP(BOOL) SysGetSystemDirectoryW(LPWSTR lpBuffer,DWORD dwSize);
SYSLIBEXP(BOOL) SysGetSystemDirectoryA(LPSTR lpBuffer,DWORD dwSize);

#ifdef UNICODE
#define SysGetSystemDirectory SysGetSystemDirectoryW
#else
#define SysGetSystemDirectory SysGetSystemDirectoryA
#endif


SYSLIBEXP(LPCWSTR) GetInstalledFireWallNameW();
SYSLIBEXP(LPCSTR) GetInstalledFireWallNameA();

#ifdef UNICODE
#define GetInstalledFireWallName GetInstalledFireWallNameW
#else
#define GetInstalledFireWallName GetInstalledFireWallNameA
#endif


SYSLIBEXP(LPCWSTR) GetInstalledAntiSpywareNameW();
SYSLIBEXP(LPCSTR) GetInstalledAntiSpywareNameA();

#ifdef UNICODE
#define GetInstalledAntiSpywareName GetInstalledAntiSpywareNameW
#else
#define GetInstalledAntiSpywareName GetInstalledAntiSpywareNameA
#endif


SYSLIBEXP(LPCWSTR) GetInstalledAntiVirusNameW();
SYSLIBEXP(LPCSTR) GetInstalledAntiVirusNameA();

#ifdef UNICODE
#define GetInstalledAntiVirusName GetInstalledAntiVirusNameW
#else
#define GetInstalledAntiVirusName GetInstalledAntiVirusNameA
#endif


SYSLIBEXP(LPCWSTR) GetInstalledProgramsW();
SYSLIBEXP(LPCSTR) GetInstalledProgramsA();

#ifdef UNICODE
#define GetInstalledPrograms GetInstalledProgramsW
#else
#define GetInstalledPrograms GetInstalledProgramsA
#endif


SYSLIBEXP(LPWSTR) SysExpandEnvironmentStringsExW(LPCWSTR lpEnvStr);
SYSLIBEXP(LPSTR) SysExpandEnvironmentStringsExA(LPCSTR lpEnvStr);

#ifdef UNICODE
#define SysExpandEnvironmentStringsEx SysExpandEnvironmentStringsExW
#else
#define SysExpandEnvironmentStringsEx SysExpandEnvironmentStringsExA
#endif


SYSLIBEXP(LPWSTR) SysFindRecycleBinW(LPCWSTR lpPath);
SYSLIBEXP(LPSTR) SysFindRecycleBinA(LPCSTR lpPath);

#ifdef UNICODE
#define SysFindRecycleBin SysFindRecycleBinW
#else
#define SysFindRecycleBin SysFindRecycleBinA
#endif


enum FS_TYPE
{
    UNKNOWN,
    FAT,
    NTFS
};

SYSLIBEXP(FS_TYPE) SysGetVolomeFSW(LPCWSTR lpPath);
SYSLIBEXP(FS_TYPE) SysGetVolomeFSA(LPCSTR lpPath);

#ifdef UNICODE
#define SysGetVolomeFS SysGetVolomeFSW
#else
#define SysGetVolomeFS SysGetVolomeFSA
#endif

SYSLIBEXP(BOOL) CreateCurrentUserEnvironmentBlock(LPVOID *lppEnvironment,BOOL bInherit);

#endif // SYSLIB_OSENV_H_INCLUDED

#ifndef FINDFILES_H_INCLUDED
#define FINDFILES_H_INCLUDED

namespace SYSLIB
{
    bool IsDotsNameW(LPWSTR lpName);
    bool PathCombineW(LPWSTR lpDest,LPCWSTR lpDir,LPCWSTR lpFile);
};

#endif // FINDFILES_H_INCLUDED

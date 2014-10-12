#ifndef OSENV_H_INCLUDED
#define OSENV_H_INCLUDED

struct ENUMUSERPROFILEDIRSINT
{
    void *lpParam;
    bool bParam;
    bool bUnicode;
    union
    {
        ENUMUSERPROFILEDIRSCALLBACKA *lpCallback;
        ENUMUSERPROFILEDIRSCALLBACKPARAMA *lpCallbackParam;
    };
};

struct ENUMUSERPROFILESINT
{
    bool bParam;
    void *lpParam;
    union
    {
        ENUMUSERPROFILESCALLBACK *lpCallback;
        ENUMUSERPROFILESCALLBACKPARAM *lpCallbackParam;
    };
};


#endif // OSENV_H_INCLUDED

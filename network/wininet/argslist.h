#ifndef ARGSLIST_H_INCLUDED
#define ARGSLIST_H_INCLUDED

enum INET_ARG_TYPE
{
    INET_ARG_STRING=0,
    INET_ARG_INT,
    INET_ARG_RAW,
    INET_ARG_FILE
};

struct INET_ARG
{
    char *lpName;

    INET_ARG_TYPE dwType;
    union
    {
        int dwValueInt;
        struct
        {
            char *lpValueStr;
            DWORD dwValueStrSize;
        };
        struct
        {
            void *lpValueRaw;
            DWORD dwValueRawSize;
        };
        struct
        {
            char *lpFullFileName;
            DWORD dwFileNameSize;
            struct
            {
                void *lpValueRaw;
                DWORD dwValueRawSize;
            } pseudo_file;
            INET_ARG *lpNextFile;
        };
    };
    INET_ARG *lpNext;
};

struct INET_ARGS_LIST
{
    HTTP_HANDLE_TYPE dwType;

    SAFE_CRITICAL_SECTION csArguments;
    INET_ARG *lpArgs;
};

#endif // ARGSLIST_H_INCLUDED

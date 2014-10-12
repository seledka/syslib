#ifndef GETWNDDESK_H_INCLUDED
#define GETWNDDESK_H_INCLUDED

#define TM_GETDESK 100500

struct HWND_TO_HDESK
{
    bool bFound;
    HDESK hDesk;
    HWND hWnd;
};

#endif // GETWNDDESK_H_INCLUDED

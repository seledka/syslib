#ifndef AV_GRABBER_H_INCLUDED
#define AV_GRABBER_H_INCLUDED

struct WMI
{
    HRESULT hResInit;
    IWbemLocator *lpLocator;
    IWbemServices *lpService;
};

#endif // AV_GRABBER_H_INCLUDED

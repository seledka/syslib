#ifndef BSOD_H_INCLUDED
#define BSOD_H_INCLUDED

typedef long (WINAPI *__RtlSetProcessIsCritical)(BOOLEAN bNew,BOOLEAN *pbOld,BOOLEAN bNeedScb);

#endif // BSOD_H_INCLUDED

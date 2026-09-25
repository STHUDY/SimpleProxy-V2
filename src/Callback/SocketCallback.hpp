#pragma once

#include "headfile.h"

typedef struct CallbackShareInfo CallbackShareInfo;
typedef struct SocketClientInfo SocketClientInfo;

void socketServerCallback(int fd, SocketClientInfo *socketClientInfo);

void socketListenerCallback();

void socketProxyWorkerSingle(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo, size_t bufferSize, CallbackShareInfo *shareInfo, std::string headText);

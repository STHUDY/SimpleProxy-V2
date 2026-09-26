#pragma once

#include "headfile.h"

typedef struct TlsClientInfo TlsClientInfo;
typedef struct SocketClientInfo SocketClientInfo;
typedef void (*TlsClientCallback)(TlsClientInfo *clientInfo);

void tlsSocketUpgradeCallback(SocketClientInfo *clientInfo, TlsClientCallback tlsCallback);

void tlsServerCallback(TlsClientInfo *tlsClientInfo);

void tlsListenerCallback();

void tlsProxyWorker(TlsClientInfo *aConnectInfo, TlsClientInfo *bConnectInfo);

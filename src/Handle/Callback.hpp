#ifndef CALLBACK_HPP
#define CALLBACK_HPP

#include "headfile.h"
// C++兼容性
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct CallbackShareInfo
    {
        bool init;
        bool close;
        float timeout;
        std::mutex *mutex;
    } CallbackShareInfo;

    // 前向声明SocketClientInfo（确保类型可见）
    typedef struct SocketClientInfo SocketClientInfo;

    // 函数声明 - 使用C链接
    void socketServerCallback(int fd, SocketClientInfo *socketClientInfo);

    void socketListenerCallback();

    void socketProxyWorkerSingle(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo, size_t bufferSize, CallbackShareInfo *shareInfo, std::string headText);

    typedef struct TlsClientInfo TlsClientInfo;

    void tlsServerCallback(int fd, TlsClientInfo *tlsClientInfo);

    void tlsListenerCallback();

    void tlsProxyWorker(TlsClientInfo *aConnectInfo, TlsClientInfo *bConnectInfo);

#ifdef __cplusplus
}
#endif

#endif // CALLBACK_HPP
#include "SocketCallback.hpp"

static void socketCreateProxyMission(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo)
{
    std::string clientAddr = std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port);

    if (!isIpAllowed(aConnectInfo->ip_str))
    {
        logOutputErrorConsole("SECURITY: Access denied - IP '" + std::string(aConnectInfo->ip_str) + "' is blocked by firewall rules");
        shutdown(aConnectInfo->fd, SHUT_RDWR);
        close(aConnectInfo->fd);

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    selectBackendTarget();

    if (connectSocketServer(bConnectInfo) < 0)
    {
        logOutputErrorConsole("Failed to establish backend connection for client " + clientAddr);
        if (aConnectInfo->fd > 0)
        {
            shutdown(aConnectInfo->fd, SHUT_RDWR);
            close(aConnectInfo->fd);
        }

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    logOutputInfoConsole("New connection established - Client: " + clientAddr + " -> Backend: " +
                         std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));

    CallbackShareInfo *shareInfo = new CallbackShareInfo;
    shareInfo->init = false;
    shareInfo->timeout = 0;
    shareInfo->mutex = new std::mutex;
    shareInfo->close = false;

    rgThreadPool.pushMission(socketProxyWorkerSingle, aConnectInfo, bConnectInfo, gClientSocketBufferSize, shareInfo, std::string("client -> proxy -> server "));
    rgThreadPool.pushMission(socketProxyWorkerSingle, bConnectInfo, aConnectInfo, gServerSocketBufferSize, shareInfo, std::string("server -> proxy -> client "));
}

void socketServerCallback(int fd, SocketClientInfo *socketClientInfo)
{

    // 必须CopySocketClientInfo
    SocketClientInfo *aConnectInfo = new SocketClientInfo(*socketClientInfo);
    SocketClientInfo *bConnectInfo = new SocketClientInfo;

    if (gConfigSocketUseThreadpoolAccept)
    {
        rgThreadPool.pushMission(socketCreateProxyMission, aConnectInfo, bConnectInfo);
    }
    else
    {
        socketCreateProxyMission(aConnectInfo, bConnectInfo);
    }
}

void socketListenerCallback()
{
    listenSocketServer(socketServerCallback);
}

void socketProxyWorkerSingle(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo, size_t bufferSize, CallbackShareInfo *shareInfo, std::string headText)
{
    std::mutex *mutex = shareInfo->mutex;
    int aSocket = aConnectInfo->fd;
    int bSocket = bConnectInfo->fd;
    char *buffer = new (std::align_val_t(64)) char[bufferSize];

    std::unique_lock<std::mutex> ulock(*mutex);

    if (shareInfo->init == false)
    {
        if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE)
        {
            logOutputInfoConsole("New connection established - Client: " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port) + " -> Backend: " +
                                 std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));

            if (gConfigSocketReadOrWriteTimeoutMs > 0)
            {
                struct timeval tv;
                tv.tv_sec = gConfigSocketReadOrWriteTimeoutMs / 1000;
                tv.tv_usec = (gConfigSocketReadOrWriteTimeoutMs % 1000) * 1000;
                setsockopt(aSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(aSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(bSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(bSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
        }

        shareInfo->close = false;
        shareInfo->init = true;
    }

    ulock.unlock();

    if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        bool isBreak = false;
        while (rgSocketServerRun)
        {
            if (shareInfo->close == true)
            {
                logOutputDebugConsole("Connection closed - Client: " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port) + " -> Backend: " +
                                      std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));
                break;
            }

            logOutputDebugConsole(headText + "Waiting for data from " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port));
            ssize_t recvLen = recv(aSocket, buffer, bufferSize, MSG_NOSIGNAL);
            if (recvLen < 0)
            {
                logOutputDebugConsole("recv error: " + std::string(strerror(errno)) + " - " + std::to_string(errno));
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    if (shareInfo->close == true)
                    {
                        logOutputDebugConsole("Connection closed - Client: " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port) + " -> Backend: " +
                                              std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));
                        break;
                    }
                    if (gConfigSocketReadOrWriteTimeoutMs > 0)
                    {
                        logOutputDebugConsole("Socket read or write timeout - " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port));
                        shareInfo->close = true;
                        isBreak = true;
                        break;
                    }
                    continue;
                }
                else if (errno == EINTR)
                {
                    continue;
                }
                isBreak = true;
                break;
            }
            else if (recvLen == 0)
            {
                isBreak = true;
                break;
            }

            logOutputDebugConsole(headText + "Read " + std::to_string(recvLen) + " bytes from " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port));
            ssize_t sentTotal = 0;
            while (sentTotal < recvLen)
            {
                ssize_t sentLen = send(bSocket, buffer + sentTotal, recvLen - sentTotal, MSG_NOSIGNAL);
                if (sentLen < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        if (shareInfo->close == true)
                        {
                            logOutputDebugConsole("Connection closed - Client: " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port) + " -> Backend: " +
                                                  std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));
                            break;
                        }
                        if (gConfigSocketReadOrWriteTimeoutMs > 0)
                        {
                            logOutputDebugConsole("Socket read or write timeout - " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port));
                            shareInfo->close = true;
                            isBreak = true;
                            break;
                        }
                        continue;
                    }
                    else if (errno == EINTR)
                    {
                        continue;
                    }
                    isBreak = true;
                    break;
                }
                else if (sentLen == 0)
                {
                    isBreak = true;
                    break;
                }
                sentTotal += sentLen;
                logOutputDebugConsole(headText + "Sent " + std::to_string(sentLen) + " bytes to " + std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));
            }

            if (isBreak)
            {
                break;
            }
        }
    }

    operator delete[](buffer, std::align_val_t(64));

    ulock.lock();
    if (shareInfo->close == true)
    {
        logOutputInfoConsole("Socket proxy worker stopped");
        shutdown(aSocket, SHUT_RDWR);
        shutdown(bSocket, SHUT_RDWR);
        close(aSocket);
        close(bSocket);
        delete aConnectInfo;
        delete bConnectInfo;
        delete shareInfo;
        ulock.unlock();
        delete mutex;
    }
    else
    {
        shareInfo->close = true;
        ulock.unlock();
    }
}
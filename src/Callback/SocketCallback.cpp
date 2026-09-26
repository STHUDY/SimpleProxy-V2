#include "SocketCallback.hpp"

static void socketCreateProxyMission(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo)
{
    std::string clientAddr = std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port);

    if (!isIpAllowed(aConnectInfo->ip_str))
    {
        logOutputErrorConsole("SECURITY: Access denied - IP '" + std::string(aConnectInfo->ip_str) + "' is blocked by firewall rules");
        netShutdownBoth(aConnectInfo->fd);
        netSocketClose(aConnectInfo->fd);

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    BackendTarget backend;
    if (!selectBackendTarget(backend))
    {
        logOutputErrorConsole("No backend available for client " + clientAddr);
        netShutdownBoth(aConnectInfo->fd);
        netSocketClose(aConnectInfo->fd);

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    if (!netSocketValid(connectSocketServer(bConnectInfo, backend.host.c_str(), backend.port)))
    {
        logOutputErrorConsole("Failed to establish backend connection for client " + clientAddr);
        if (netSocketValid(aConnectInfo->fd))
        {
            netShutdownBoth(aConnectInfo->fd);
            netSocketClose(aConnectInfo->fd);
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

void socketServerCallback(SocketClientInfo *socketClientInfo)
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
    SOCKET_T aSocket = aConnectInfo->fd;
    SOCKET_T bSocket = bConnectInfo->fd;
    char *buffer = (char *)netAlignedAlloc(bufferSize, 64);
    if (buffer == nullptr)
    {
        // 分配失败不能提前 return：另一个方向的 worker 还在等 shareInfo->close 变化，
        // 直接退出会让它一直挂在 recv 上。照常走下面的退出协议即可，
        // 只是不做任何转发。
        logOutputErrorConsole("Socket proxy worker stopped - failed to allocate " + std::to_string(bufferSize) + " bytes transfer buffer");
    }

    std::unique_lock<std::mutex> ulock(*mutex);

    if (shareInfo->init == false)
    {
        if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE)
        {
            logOutputInfoConsole("New connection established - Client: " + std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port) + " -> Backend: " +
                                 std::string(bConnectInfo->ip_str) + ":" + std::to_string(bConnectInfo->port));

            if (gConfigSocketReadOrWriteTimeoutMs > 0)
            {
                netSetRecvTimeoutMs(aSocket, gConfigSocketReadOrWriteTimeoutMs);
                netSetSendTimeoutMs(aSocket, gConfigSocketReadOrWriteTimeoutMs);
                netSetRecvTimeoutMs(bSocket, gConfigSocketReadOrWriteTimeoutMs);
                netSetSendTimeoutMs(bSocket, gConfigSocketReadOrWriteTimeoutMs);
            }
        }

        shareInfo->close = false;
        shareInfo->init = true;
    }

    ulock.unlock();

    if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE && buffer != nullptr)
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
            NET_SSIZE_T recvLen = recv(aSocket, buffer, bufferSize, SOCKET_SEND_FLAGS);
            if (recvLen < 0)
            {
                int recvErr = netLastError();
                logOutputDebugConsole("recv error: " + std::string(netErrorString(recvErr)) + " - " + std::to_string(recvErr));
                if (netIsWouldBlock(recvErr))
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
                        isBreak = true;
                        break;
                    }
                    continue;
                }
                else if (netIsInterrupted(recvErr))
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
            NET_SSIZE_T sentTotal = 0;
            while (sentTotal < recvLen)
            {
                NET_SSIZE_T sentLen = send(bSocket, buffer + sentTotal, (int)(recvLen - sentTotal), SOCKET_SEND_FLAGS);
                if (sentLen < 0)
                {
                    int sendErr = netLastError();
                    if (netIsWouldBlock(sendErr))
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
                            isBreak = true;
                            break;
                        }
                        continue;
                    }
                    else if (netIsInterrupted(sendErr))
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

    netAlignedFree(buffer);

    ulock.lock();
    if (shareInfo->close == true)
    {
        logOutputInfoConsole("Socket proxy worker stopped");
        netShutdownBoth(aSocket);
        netShutdownBoth(bSocket);
        netSocketClose(aSocket);
        netSocketClose(bSocket);
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

#include "Callback.hpp"

static bool isIpAllowed(const std::string &ip_str)
{
    auto ban_it = std::find(gServerConnectBanIpsList.begin(), gServerConnectBanIpsList.end(), ip_str);
    if (ban_it != gServerConnectBanIpsList.end())
    {
        return false; // IP 被禁止
    }

    if (gServerConnectAllowIpsList.empty())
    {
        return true;
    }

    // 如果白名单不为空，只有在白名单中的 IP 才能访问
    auto allow_it = std::find(gServerConnectAllowIpsList.begin(), gServerConnectAllowIpsList.end(), ip_str);
    if (allow_it != gServerConnectAllowIpsList.end())
    {
        return true;
    }
    else
    {
        return false;
    }
}

void socketServerCallback(int fd, SocketClientInfo *socketClientInfo)
{
    // 必须CopySocketClientInfo
    std::string clientAddr = std::string(socketClientInfo->ip_str) + ":" + std::to_string(socketClientInfo->port);

    if (!isIpAllowed(socketClientInfo->ip_str))
    {
        logOutputErrorConsole("SECURITY: Access denied - IP '" + std::string(socketClientInfo->ip_str) + "' is blocked by firewall rules");
        shutdown(socketClientInfo->fd, SHUT_RDWR);
        close(socketClientInfo->fd);
        return;
    }

    // 在非阻塞模式下设置socket为非阻塞以进行快速检测
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        logOutputErrorConsole("Failed to get socket flags for client " + clientAddr + " - " + strerror(errno));
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        logOutputErrorConsole("Failed to set socket to non-blocking for client " + clientAddr + " - " + strerror(errno));
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    char detect_buffer[1024];
    ssize_t bytes_read = recv(fd, detect_buffer, sizeof(detect_buffer), MSG_PEEK);

    // 恢复原始socket标志
    if (fcntl(fd, F_SETFL, flags) == -1)
    {
        logOutputWarnConsole("Failed to restore socket flags for client " + clientAddr + " - " + strerror(errno));
        // 继续处理，但记录警告
    }

    if (bytes_read == 0)
    {
        // 客户端立即关闭连接
        logOutputDebugConsole("Client " + clientAddr + " closed connection immediately during handshake");
        close(fd);
        return;
    }
    else
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            logOutputErrorConsole("Error reading from client socket " + clientAddr + " - " + strerror(errno));
            close(fd);
            return;
        }
        // 如果是EAGAIN/EWOULDBLOCK，说明没有数据可读，继续正常处理
    }

    SocketClientInfo *aConnectInfo = new SocketClientInfo(*socketClientInfo);
    SocketClientInfo *bConnectInfo = new SocketClientInfo;

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

void socketListenerCallback()
{
    listenSocketServer(socketServerCallback);
}

void socketProxyWorkerSingle(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo, size_t bufferSize, CallbackShareInfo *shareInfo, std::string headText)
{
    std::mutex *mutex = shareInfo->mutex;
    int aSocket = aConnectInfo->fd;
    int bSocket = bConnectInfo->fd;
    char *buffer = new char[bufferSize];
    std::unique_lock<std::mutex> ulock(*mutex);

    if (shareInfo->init == false)
    {
        if (gConfigSocketNoBlockReadOrWrite)
        {
            int flags;
            flags = fcntl(aSocket, F_GETFL, 0);
            if (flags != -1)
                fcntl(aSocket, F_SETFL, flags | O_NONBLOCK);
            flags = fcntl(bSocket, F_GETFL, 0);
            if (flags != -1)
                fcntl(bSocket, F_SETFL, flags | O_NONBLOCK);
        }
        else if (gConfigSocketReadOrWriteTimeoutMs > 0)
        {
            struct timeval tv;
            tv.tv_sec = gConfigSocketReadOrWriteTimeoutMs / 1000;
            tv.tv_usec = (gConfigSocketReadOrWriteTimeoutMs % 1000) * 1000;
            setsockopt(aSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(aSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(bSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(bSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
        shareInfo->init = true;
    }

    if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        ulock.unlock();
        bool isBreak = false;
        struct timespec lastPoll, now;
        if (gConfigSocketNoBlockReadOrWrite)
        {
            clock_gettime(CLOCK_MONOTONIC, &lastPoll);
        }
        while (rgSocketServerRun)
        {
            if (shareInfo->close == true)
            {
                break;
            }

            if (shareInfo->timeout > gConfigSocketReadOrWriteTimeoutMs)
            {
                break;
            }

            ssize_t recvLen = recv(aSocket, buffer, bufferSize, 0);
            if (recvLen < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    long elapsedUs = (now.tv_sec - lastPoll.tv_sec) * 1000000L +
                                     (now.tv_nsec - lastPoll.tv_nsec) / 1000L;
                    long intervalUs = gConfigSocketPollingIntervalMs * 1000L;

                    shareInfo->timeout += (float)elapsedUs / 2000.0f;

                    if (elapsedUs < intervalUs)
                    {
                        usleep(intervalUs - elapsedUs);
                    }
                    clock_gettime(CLOCK_MONOTONIC, &lastPoll);
                    continue;
                }
                isBreak = true;
                break;
            }
            if (recvLen == 0)
            {
                isBreak = true;
            }
            ssize_t sentTotal = 0;
            while (sentTotal < recvLen)
            {
                ssize_t sentLen = send(aSocket, buffer + sentTotal, recvLen - sentTotal, 0);
                if (sentLen < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        clock_gettime(CLOCK_MONOTONIC, &now);
                        long elapsedUs = (now.tv_sec - lastPoll.tv_sec) * 1000000L +
                                         (now.tv_nsec - lastPoll.tv_nsec) / 1000L;
                        long intervalUs = gConfigSocketPollingIntervalMs * 1000L;

                        shareInfo->timeout += (float)elapsedUs / 2000.0f;

                        if (elapsedUs < intervalUs)
                        {
                            usleep(intervalUs - elapsedUs);
                        }
                        clock_gettime(CLOCK_MONOTONIC, &lastPoll);
                        continue;
                    }
                    isBreak = true;
                    break;
                }
                sentTotal += sentLen;
            }

            if (isBreak)
            {
                break;
            }
        }
    }

    delete[] buffer;

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
        ulock.unlock();
        shareInfo->close = true;
    }
}

void tlsServerCallback(int fd, TlsClientInfo *tlsClientInfo)
{
    std::string clientAddr = std::string(tlsClientInfo->ip_str) + ":" + std::to_string(tlsClientInfo->port);

    if (!isIpAllowed(tlsClientInfo->ip_str))
    {
        logOutputErrorConsole("SECURITY: TLS Access denied - IP '" + std::string(tlsClientInfo->ip_str) + "' is blocked by firewall rules");
        if (tlsClientInfo->ssl)
        {
            SSL_shutdown(tlsClientInfo->ssl);
            SSL_free(tlsClientInfo->ssl);
            SSL_CTX_free(tlsClientInfo->ssl_ctx);
        }
        if (tlsClientInfo->fd >= 0)
        {
            close(tlsClientInfo->fd);
        }
        return;
    }

    // 必须复制TlsClientInfo
    TlsClientInfo *aConnectInfo = new TlsClientInfo(*tlsClientInfo);
    TlsClientInfo *bConnectInfo = new TlsClientInfo;

    std::string sniStr;
    const char *sni = NULL;

    if (gClientTlsSniChar == "")
    {
        sni = SSL_get_servername(aConnectInfo->ssl, TLSEXT_NAMETYPE_host_name);
        sniStr = sni;
    }
    else
    {
        sniStr = gClientTlsSniChar;
        sni = sniStr.c_str();
    }

    if (connectTlsServer(bConnectInfo, sni) < 0)
    {
        logOutputErrorConsole("Failed to establish TLS backend connection for client " + clientAddr + " (SNI: " + sniStr + ")");
        if (aConnectInfo->ssl)
        {
            SSL_shutdown(aConnectInfo->ssl);
            SSL_free(aConnectInfo->ssl);
            SSL_CTX_free(aConnectInfo->ssl_ctx);
        }
        if (aConnectInfo->fd >= 0)
        {
            close(aConnectInfo->fd);
        }

        if (bConnectInfo->ssl)
        {
            SSL_shutdown(bConnectInfo->ssl);
            SSL_free(bConnectInfo->ssl);
            SSL_CTX_free(bConnectInfo->ssl_ctx);
            bConnectInfo->ssl = NULL; // 避免重复释放
        }
        if (bConnectInfo->fd >= 0)
        {
            close(bConnectInfo->fd);
            bConnectInfo->fd = -1; // 标记为已关闭
        }

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    logOutputInfoConsole("New TLS connection established - Client: " + clientAddr + " (SNI: " + sniStr + ") -> Backend");

    rgThreadPool.pushMission(tlsProxyWorker, aConnectInfo, bConnectInfo);
}

void tlsListenerCallback()
{
    listenTlsServer(tlsServerCallback);
}

void tlsProxyWorker(TlsClientInfo *aConnectInfo, TlsClientInfo *bConnectInfo)
{
    SSL *aSsl = aConnectInfo->ssl;
    SSL *bSsl = bConnectInfo->ssl;
    SSL_CTX *aSslCtx = aConnectInfo->ssl_ctx;
    SSL_CTX *bSslCtx = bConnectInfo->ssl_ctx;
    int aSocket = aConnectInfo->fd;
    int bSocket = bConnectInfo->fd;

    // 初始化为-1表示未创建
    int epollFd = -1;

    char *bufferAtoB = new char[gClientSocketBufferSize];
    char *bufferBtoA = new char[gServerSocketBufferSize];

    // 用于标记是否需要执行清理逻辑的 lambda
    auto cleanup = [&]()
    {
        if (epollFd != -1)
        {
            close(epollFd);
        }

        delete[] bufferAtoB;
        delete[] bufferBtoA;

        if (bSsl)
        {
            SSL_shutdown(bSsl);
            SSL_free(bSsl);
            SSL_CTX_free(bSslCtx);
        }
        if (bSocket >= 0)
        {
            close(bSocket);
        }
        delete bConnectInfo;

        if (aSsl)
        {
            SSL_shutdown(aSsl);
            SSL_free(aSsl);
            SSL_CTX_free(aSslCtx);
        }
        if (aSocket >= 0)
        {
            close(aSocket);
        }
        delete aConnectInfo;

        logOutputInfoConsole("TLS proxy worker stopped");
    };

    if (gConfigTlsNoBlockReadOrWrite)
    {
        int flags;
        flags = fcntl(aSocket, F_GETFL, 0);
        if (flags != -1)
            fcntl(aSocket, F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(bSocket, F_GETFL, 0);
        if (flags != -1)
            fcntl(bSocket, F_SETFL, flags | O_NONBLOCK);
    }
    else if (gConfigTlsReadOrWriteTimeoutMs > 0)
    {
        struct timeval tv;
        tv.tv_sec = gConfigTlsReadOrWriteTimeoutMs / 1000;
        tv.tv_usec = (gConfigTlsReadOrWriteTimeoutMs % 1000) * 1000;
        setsockopt(aSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(aSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(bSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(bSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    logOutputInfoConsole("TLS proxy worker started");

    if (SSL_is_init_finished(aSsl) == 0 || SSL_is_init_finished(bSsl) == 0)
    {
        logOutputErrorConsole("CRITICAL: SSL handshake not completed before proxy worker!");
        cleanup();
        return;
    }
    logOutputDebugConsole("TLS proxy started with verified handshake completion");

    epollFd = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd == -1)
    {
        logOutputErrorConsole("tls Proxy: Failed to create epoll instance: " + std::string(strerror(errno)));
        cleanup();
        return;
    }

    logOutputDebugConsole("tls Proxy: create epoll success");
    struct epoll_event epollEventConnectA{}, epollEventConnectB{}, events[2];
    epollEventConnectA.events = EPOLLIN;
    epollEventConnectA.data.fd = aSocket;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, aSocket, &epollEventConnectA) == -1)
    {
        logOutputErrorConsole("tls Proxy: Failed to add aSocket to epoll: " + std::string(strerror(errno)));
        cleanup();
        return;
    }

    epollEventConnectB.events = EPOLLIN;
    epollEventConnectB.data.fd = bSocket;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, bSocket, &epollEventConnectB) == -1)
    {
        logOutputErrorConsole("tls Proxy: Failed to add bSocket to epoll: " + std::string(strerror(errno)));
        cleanup();
        return;
    }

    const float PollTimeSeconds = (float)gConfigTlsPollingIntervalMs / 1000.0f;
    float timeout = 0;

    while (rgTlsServerRun)
    {
        int eventsNumber = epoll_wait(epollFd, events, 2, gConfigTlsPollingIntervalMs);
        if (eventsNumber == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            logOutputErrorConsole("tls Proxy: Failed to wait for epoll events: " + std::string(strerror(errno)));
            break;
        }
        if (eventsNumber == 0)
        {
            timeout += PollTimeSeconds;
            if (gConfigTlsReadOrWriteTimeoutMs > 0 && timeout > gConfigTlsReadOrWriteTimeoutMs)
            {
                logOutputWarnConsole("tls Proxy: Timeout while waiting for epoll events " + std::to_string(timeout));
                break;
            }
            else
            {
                continue;
            }
        }

        timeout = 0;

        bool isBreak = false;

        for (int i = 0; i < eventsNumber;)
        {
            int activeFd = events[i].data.fd;
            uint32_t eventFlags = events[i].events;
            if (eventFlags & EPOLLIN)
            {
                SSL *srcSsl = activeFd == aSocket ? aSsl : bSsl;
                SSL *dstSsl = activeFd == aSocket ? bSsl : aSsl;
                bool isAtoB = activeFd == aSocket;
                char *buffer = isAtoB ? bufferAtoB : bufferBtoA;
                int bufferSize = isAtoB ? gClientSocketBufferSize : gServerSocketBufferSize;

                int sslReadNum = SSL_read(srcSsl, buffer, bufferSize);
                if (gConfigTlsNoBlockReadOrWrite == false)
                {
                    if (SSL_pending(srcSsl) == 0)
                    {
                        timeout = 0;
                        i++;
                    }
                }
                if (sslReadNum > 0)
                {
                    logOutputDebugConsole((isAtoB ? "tls client -> proxy: " : "tls server -> proxy: ") + std::to_string(sslReadNum) + " bytes from aSocket");
                    size_t sentTotal = 0;
                    while (rgTlsServerRun && sentTotal < sslReadNum)
                    {
                        int sentNum = SSL_write(dstSsl, buffer + sentTotal, sslReadNum - sentTotal);
                        if (sentNum > 0)
                        {
                            logOutputDebugConsole((isAtoB ? "tls proxy -> server: " : "tls proxy -> client: ") + std::to_string(sentNum) + " bytes to bSocket");
                            sentTotal += sentNum;
                        }
                        else
                        {
                            int sendErrno = SSL_get_error(dstSsl, sentNum);
                            if (sendErrno == SSL_ERROR_WANT_WRITE)
                            {
                                fd_set writefds;
                                FD_ZERO(&writefds);
                                FD_SET(activeFd, &writefds);

                                struct timeval timeoutUse = {
                                    static_cast<time_t>(gConfigSocketPollingIntervalMs / 1000),
                                    static_cast<suseconds_t>((gConfigSocketPollingIntervalMs % 1000) * 1000)};

                                int ret = select(activeFd + 1, NULL, &writefds, NULL, &timeoutUse);
                                if (ret <= 0)
                                {
                                    logOutputErrorConsole("tls Proxy: bSsl write select failed: " + std::string(strerror(errno)));
                                    isBreak = true;
                                    break;
                                }
                                timeout += PollTimeSeconds;
                                if (timeout > gConfigTlsConnectTimeoutMs)
                                {
                                    logOutputWarnConsole("tls Proxy: Timeout while waiting for epoll events " + std::to_string(timeout));
                                    isBreak = true;
                                    break;
                                }
                                continue;
                            }
                            if (sendErrno == SSL_ERROR_ZERO_RETURN)
                                logOutputInfoConsole("tls Proxy: bSsl closed connection");
                            else
                                logOutputErrorConsole("tls Proxy: bSsl write failed code: " + std::to_string(sendErrno));
                            isBreak = true;
                            break;
                        }
                    }
                }
                else
                {
                    int recvErrno = SSL_get_error(srcSsl, sslReadNum);
                    if (recvErrno == SSL_ERROR_WANT_READ)
                    {
                        timeout = 0;
                        i++;
                        continue;
                    }
                    else if (recvErrno == SSL_ERROR_SYSCALL)
                    {
                        int sys_errno = errno;
                        if (sys_errno == 0)
                        {
                            logOutputInfoConsole("tls Proxy: aSsl connection closed cleanly");
                        }
                        else if (sys_errno == ECONNRESET || sys_errno == EPIPE)
                        {
                            logOutputInfoConsole("tls Proxy: aSsl connection reset by peer");
                        }
                        else
                        {
                            logOutputErrorConsole("tls Proxy: aSsl read syscall error: " + std::string(strerror(sys_errno)));
                        }
                    }
                    else if (recvErrno == SSL_ERROR_ZERO_RETURN)
                        logOutputInfoConsole("tls Proxy: aSsl closed connection");
                    else
                        logOutputErrorConsole("tls Proxy: aSsl read failed code: " + std::to_string(recvErrno));
                    isBreak = true;
                    break;
                }
            }
            else
            {
                logOutputErrorConsole("tls Proxy: " + std::to_string(eventFlags) + " on fd " + std::to_string(activeFd));
                isBreak = true;
            }

            if (isBreak)
            {
                break;
            }
        }

        if (isBreak)
        {
            break;
        }
    }

    cleanup();
}
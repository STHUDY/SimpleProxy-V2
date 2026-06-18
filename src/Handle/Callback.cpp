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
    char *buffer = new char[bufferSize];

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
                        shareInfo->close == true;
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
                if (gConfigSocketReadOrWriteTimeoutMs > 0 && shareInfo->timeout > gConfigSocketReadOrWriteTimeoutMs)
                {
                    break;
                }
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
                            shareInfo->close == true;
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
        shareInfo->close = true;
        ulock.unlock();
    }
}

static void tlsSocketUpgradeTlsAccept(SocketClientInfo *aConnectInfo, TlsClientCallback tlsCallback)
{
    int aSocket = aConnectInfo->fd;

    if (gConfigTlsSslIoUseMode == CONNECT_USE_IO_NONE)
    {
        if (gConfigTlsAcceptTimeoutMs > 0)
        {
            struct timeval tv;
            tv.tv_sec = gConfigTlsAcceptTimeoutMs / 1000;
            tv.tv_usec = (gConfigTlsAcceptTimeoutMs % 1000) * 1000;

            setsockopt(aSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(aSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }

        SSL_CTX *ctx = createContext(true);

        if (configureServerContext(ctx) == false)
        {
            logOutputErrorConsole("Listen tls server have a mistake: configure server context error");
            SSL_CTX_free(ctx);
            close(aSocket);
            delete aConnectInfo;
            return;
        }

        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            logOutputErrorConsole("Listen tls server have a mistake: SSL_new error");
            SSL_CTX_free(ctx);
            close(aSocket);
            delete aConnectInfo;
            return;
        }

        int sslAccept = 0;
        int sslConnErr = 0;

        while (rgTlsServerRun)
        {
            sslAccept = SSL_accept(ssl);
            sslConnErr = SSL_ERROR_NONE;
            if (sslAccept == 1)
            {
                TlsClientInfo tlsClientInfo = {0};
                tlsClientInfo.fd = aSocket;
                tlsClientInfo.ssl_ctx = ctx;
                tlsClientInfo.ssl = ssl;
                memcpy(&tlsClientInfo.addr, &aConnectInfo->addr, sizeof(aConnectInfo->addr_len));
                tlsClientInfo.addr_len = sizeof(aConnectInfo->addr);
                strncpy(tlsClientInfo.ip_str, aConnectInfo->ip_str, INET_ADDRSTRLEN);
                tlsClientInfo.port = aConnectInfo->port;
                tlsCallback(aSocket, &tlsClientInfo);
                break;
            }

            sslConnErr = SSL_get_error(ssl, sslAccept);

            if (sslConnErr == SSL_ERROR_WANT_READ || sslConnErr == SSL_ERROR_WANT_WRITE)
            {
                logOutputErrorConsole("SSL_accept select error: " + std::to_string(errno));
                break;
            }
            else if (sslConnErr == SSL_ERROR_SYSCALL)
            {
                // 检查系统调用的errno是否代表超时
                if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    logOutputErrorConsole("SSL_accept syscall timeout: errno=" + std::to_string(errno));
                }
                else
                {
                    logOutputErrorConsole("SSL_accept syscall error: errno=" + std::to_string(errno));
                }
                break;
            }
            else
            {
                logOutputErrorConsole("SSL_accept fatal SSL error: " + std::to_string(sslConnErr));
                break;
            }
        }

        if (sslConnErr != SSL_ERROR_NONE)
        {
            // 获取详细错误字符串
            char errBuf[256];
            unsigned long err = ERR_get_error();
            ERR_error_string_n(err, errBuf, sizeof(errBuf));

            std::ostringstream oss;
            oss << "SSL accept failed for client " << aConnectInfo->ip_str << ":" << aConnectInfo->port
                << " - " << errBuf;
            logOutputErrorConsole(oss.str());

            if (ssl)
            {
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            }

            if (aConnectInfo >= 0)
                close(aSocket);
        }

        delete aConnectInfo;
    }
}

static void tlsCreateProxyMission(TlsClientInfo *aConnectInfo, TlsClientInfo *bConnectInfo)
{
    std::string clientAddr = std::string(aConnectInfo->ip_str) + ":" + std::to_string(aConnectInfo->port);

    if (!isIpAllowed(aConnectInfo->ip_str))
    {
        logOutputErrorConsole("SECURITY: TLS Access denied - IP '" + std::string(aConnectInfo->ip_str) + "' is blocked by firewall rules");
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

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

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

void tlsSocketUpgradeCallback(SocketClientInfo *clientInfo, TlsClientCallback tlsCallback)
{
    SocketClientInfo *aConnectInfo = new SocketClientInfo(*clientInfo);
    if (gConfigTlsUseThreadpoolAccept)
    {
        rgThreadPool.pushMission(tlsSocketUpgradeTlsAccept, aConnectInfo, tlsCallback);
    }
    else
    {
        tlsSocketUpgradeTlsAccept(aConnectInfo, tlsCallback);
    }
}

void tlsServerCallback(int fd, TlsClientInfo *tlsClientInfo)
{

    // 必须复制TlsClientInfo
    TlsClientInfo *aConnectInfo = new TlsClientInfo(*tlsClientInfo);
    TlsClientInfo *bConnectInfo = new TlsClientInfo;

    if (gConfigTlsUseThreadpoolSslConnect)
    {
        rgThreadPool.pushMission(tlsCreateProxyMission, aConnectInfo, bConnectInfo);
    }
    else
    {
        tlsCreateProxyMission(aConnectInfo, bConnectInfo);
    }
}

void tlsListenerCallback()
{
    listenTlsServer(tlsSocketUpgradeCallback, tlsServerCallback);
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

    logOutputInfoConsole("TLS proxy worker started");

    if (SSL_is_init_finished(aSsl) == 0 || SSL_is_init_finished(bSsl) == 0)
    {
        logOutputErrorConsole("CRITICAL: SSL handshake not completed before proxy worker!");
        cleanup();
        return;
    }
    logOutputDebugConsole("TLS proxy started with verified handshake completion");

    if (gConfigTlsReadOrWriteTimeoutMs > 0)
    {
        struct timeval tv;
        tv.tv_sec = gConfigTlsReadOrWriteTimeoutMs / 1000;
        tv.tv_usec = (gConfigTlsReadOrWriteTimeoutMs % 1000) * 1000;
        setsockopt(aSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(aSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(bSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(bSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

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
#include "TlsCallback.hpp"

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

        SSL_set_fd(ssl, aSocket);

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
                memcpy(&tlsClientInfo.addr, &aConnectInfo->addr, sizeof(aConnectInfo->addr));
                tlsClientInfo.addr_len = aConnectInfo->addr_len;
                strncpy(tlsClientInfo.ip_str, aConnectInfo->ip_str, INET_ADDRSTRLEN);
                tlsClientInfo.port = aConnectInfo->port;
                tlsCallback(aSocket, &tlsClientInfo);
                logOutputDebugConsole("TLS Accept success");
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

            if (aSocket >= 0)
                close(aSocket);
        }
    }

    delete aConnectInfo;
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

    if (gClientTlsSniChar == NULL || gClientTlsSniChar[0] == '\0')
    {
        // 未配置 sni：透传客户端握手带来的 SNI。客户端可能没带，
        // SSL_get_servername() 会返回 NULL，不能拿它构造 std::string。
        sni = SSL_get_servername(aConnectInfo->ssl, TLSEXT_NAMETYPE_host_name);
        sniStr = (sni != NULL) ? sni : "";
    }
    else
    {
        sniStr = gClientTlsSniChar;
        sni = sniStr.c_str();
    }

    BackendTarget backend;
    if (!selectBackendTarget(backend))
    {
        logOutputErrorConsole("No backend available for TLS client " + clientAddr);
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

    if (connectTlsServer(bConnectInfo, sni, backend.host.c_str(), backend.port) < 0)
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

    logOutputDebugConsole("create tls proxy thread");

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

    char *bufferAtoB = new (std::align_val_t(64)) char[gClientSocketBufferSize];
    char *bufferBtoA = new (std::align_val_t(64)) char[gServerSocketBufferSize];

    // 用于标记是否需要执行清理逻辑的 lambda
    auto cleanup = [&]()
    {
        if (epollFd != -1)
        {
            close(epollFd);
        }

        operator delete[](bufferAtoB, std::align_val_t(64));
        operator delete[](bufferBtoA, std::align_val_t(64));

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

    // timeout 统一以毫秒累计，与两个 *TimeoutMs 配置项同单位
    const float pollTimeMs = (float)gConfigTlsPollingIntervalMs;
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
            timeout += pollTimeMs;
            if (gConfigTlsReadOrWriteTimeoutMs > 0 && timeout >= (float)gConfigTlsReadOrWriteTimeoutMs)
            {
                logOutputWarnConsole("tls Proxy: idle timeout after " + std::to_string((int)timeout) + "ms");
                break;
            }
            else
            {
                continue;
            }
        }

        timeout = 0;

        bool isBreak = false;

        // epoll 是水平触发：一次事件只做一次 SSL_read/SSL_write，
        // 剩余数据会再次触发 EPOLLIN，不需要靠 SSL_pending() 手工排空。
        for (int i = 0; i < eventsNumber; i++)
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
                                // 必须等目标端可写：a->b 时目标是 bSocket，反之是 aSocket
                                int dstSocket = isAtoB ? bSocket : aSocket;

                                fd_set writefds;
                                FD_ZERO(&writefds);
                                FD_SET(dstSocket, &writefds);

                                struct timeval timeoutUse = {
                                    static_cast<time_t>(gConfigSocketPollingIntervalMs / 1000),
                                    static_cast<suseconds_t>((gConfigSocketPollingIntervalMs % 1000) * 1000)};

                                int ret = select(dstSocket + 1, NULL, &writefds, NULL, &timeoutUse);
                                if (ret <= 0)
                                {
                                    logOutputErrorConsole("tls Proxy: bSsl write select failed: " + std::string(strerror(errno)));
                                    isBreak = true;
                                    break;
                                }
                                timeout += pollTimeMs;
                                if (gConfigTlsConnectTimeoutMs > 0 && timeout >= (float)gConfigTlsConnectTimeoutMs)
                                {
                                    logOutputWarnConsole("tls Proxy: write timeout after " + std::to_string((int)timeout) + "ms");
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
                        continue;   // i 由 for 语句自增
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
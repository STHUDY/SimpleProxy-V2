#include "TlsCallback.hpp"

static void tlsSocketUpgradeTlsAccept(SocketClientInfo *aConnectInfo, TlsClientCallback tlsCallback)
{
    SOCKET_T aSocket = aConnectInfo->fd;

    if (gConfigTlsSslIoUseMode == CONNECT_USE_IO_NONE)
    {
        if (gConfigTlsAcceptTimeoutMs > 0)
        {
            netSetRecvTimeoutMs(aSocket, gConfigTlsAcceptTimeoutMs);
            netSetSendTimeoutMs(aSocket, gConfigTlsAcceptTimeoutMs);
        }

        SSL_CTX *ctx = createContext(true);

        if (configureServerContext(ctx) == false)
        {
            logOutputErrorConsole("Listen tls server have a mistake: configure server context error");
            SSL_CTX_free(ctx);
            netSocketClose(aSocket);
            delete aConnectInfo;
            return;
        }

        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            logOutputErrorConsole("Listen tls server have a mistake: SSL_new error");
            SSL_CTX_free(ctx);
            netSocketClose(aSocket);
            delete aConnectInfo;
            return;
        }

        // SSL_set_fd 的形参是 int：OpenSSL 在所有平台都用 int 接 fd。
        // Windows 的 SOCKET 是 64 位句柄，这里必须显式收窄 —— 实际句柄值远小于 INT_MAX。
        SSL_set_fd(ssl, (int)aSocket);

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
                tlsCallback(&tlsClientInfo);
                logOutputDebugConsole("TLS Accept success");
                break;
            }

            sslConnErr = SSL_get_error(ssl, sslAccept);

            if (sslConnErr == SSL_ERROR_WANT_READ || sslConnErr == SSL_ERROR_WANT_WRITE)
            {
                logOutputErrorConsole("SSL_accept select error: " + std::to_string(netLastError()));
                break;
            }
            else if (sslConnErr == SSL_ERROR_SYSCALL)
            {
                int syscallErr = netLastError();
                if (syscallErr == 0)
                {
                    logOutputErrorConsole("SSL_accept syscall closed: no error reported");
                }
                else if (netIsTimeout(syscallErr) || netIsWouldBlock(syscallErr))
                {
                    logOutputErrorConsole("SSL_accept syscall timeout: errno=" + std::to_string(syscallErr));
                }
                else
                {
                    logOutputErrorConsole("SSL_accept syscall error: errno=" + std::to_string(syscallErr));
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

            if (netSocketValid(aSocket))
                netSocketClose(aSocket);
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
        if (netSocketValid(aConnectInfo->fd))
        {
            netSocketClose(aConnectInfo->fd);
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
        if (netSocketValid(aConnectInfo->fd))
        {
            netSocketClose(aConnectInfo->fd);
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
        if (netSocketValid(aConnectInfo->fd))
        {
            netSocketClose(aConnectInfo->fd);
        }

        if (bConnectInfo->ssl)
        {
            SSL_shutdown(bConnectInfo->ssl);
            SSL_free(bConnectInfo->ssl);
            SSL_CTX_free(bConnectInfo->ssl_ctx);
            bConnectInfo->ssl = NULL; // 避免重复释放
        }
        if (netSocketValid(bConnectInfo->fd))
        {
            netSocketClose(bConnectInfo->fd);
            bConnectInfo->fd = SOCKET_INVALID; // 标记为已关闭
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

void tlsServerCallback(TlsClientInfo *tlsClientInfo)
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
    SOCKET_T aSocket = aConnectInfo->fd;
    SOCKET_T bSocket = bConnectInfo->fd;

    // 初始化为 NULL 表示未创建
    struct PlatformWaitSet *waitSet = NULL;

    char *bufferAtoB = (char *)netAlignedAlloc((size_t)gClientSocketBufferSize, 64);
    char *bufferBtoA = (char *)netAlignedAlloc((size_t)gServerSocketBufferSize, 64);

    // 用于标记是否需要执行清理逻辑的 lambda
    auto cleanup = [&]()
    {
        if (waitSet != NULL)
        {
            netWaitSetDestroy(waitSet);
        }

        netAlignedFree(bufferAtoB);
        netAlignedFree(bufferBtoA);

        if (bSsl)
        {
            SSL_shutdown(bSsl);
            SSL_free(bSsl);
            SSL_CTX_free(bSslCtx);
        }
        if (netSocketValid(bSocket))
        {
            netSocketClose(bSocket);
        }
        delete bConnectInfo;

        if (aSsl)
        {
            SSL_shutdown(aSsl);
            SSL_free(aSsl);
            SSL_CTX_free(aSslCtx);
        }
        if (netSocketValid(aSocket))
        {
            netSocketClose(aSocket);
        }
        delete aConnectInfo;

        logOutputInfoConsole("TLS proxy worker stopped");
    };

    logOutputInfoConsole("TLS proxy worker started");

    if (bufferAtoB == nullptr || bufferBtoA == nullptr)
    {
        // netAlignedAlloc 失败返回 NULL，而 SSL_read 会直接往这个指针写，
        // 非空长度配空指针就是访问违例。cleanup() 里 free(NULL) 是安全的。
        logOutputErrorConsole("CRITICAL: Failed to allocate TLS transfer buffers (client=" + std::to_string(gClientSocketBufferSize) +
                              " bytes, server=" + std::to_string(gServerSocketBufferSize) + " bytes) before proxy worker!");
        cleanup();
        return;
    }

    if (SSL_is_init_finished(aSsl) == 0 || SSL_is_init_finished(bSsl) == 0)
    {
        logOutputErrorConsole("CRITICAL: SSL handshake not completed before proxy worker!");
        cleanup();
        return;
    }
    logOutputDebugConsole("TLS proxy started with verified handshake completion");

    if (gConfigTlsReadOrWriteTimeoutMs > 0)
    {
        netSetRecvTimeoutMs(aSocket, gConfigTlsReadOrWriteTimeoutMs);
        netSetSendTimeoutMs(aSocket, gConfigTlsReadOrWriteTimeoutMs);
        netSetRecvTimeoutMs(bSocket, gConfigTlsReadOrWriteTimeoutMs);
        netSetSendTimeoutMs(bSocket, gConfigTlsReadOrWriteTimeoutMs);
    }

    waitSet = netWaitSetCreate();
    if (waitSet == NULL)
    {
        logOutputErrorConsole("tls Proxy: Failed to create wait set: " + std::string(netErrorString(netLastError())));
        cleanup();
        return;
    }

    logOutputDebugConsole("tls Proxy: create wait set success");
    if (netWaitSetAdd(waitSet, aSocket) == -1)
    {
        logOutputErrorConsole("tls Proxy: Failed to add aSocket to wait set: " + std::string(netErrorString(netLastError())));
        cleanup();
        return;
    }

    if (netWaitSetAdd(waitSet, bSocket) == -1)
    {
        logOutputErrorConsole("tls Proxy: Failed to add bSocket to wait set: " + std::string(netErrorString(netLastError())));
        cleanup();
        return;
    }

    // 每轮等待的 fd 与结果：Linux 走 epoll，Windows 走 WSAPoll，循环体本身不感知平台
    SOCKET_T waitFds[2] = {aSocket, bSocket};
    int waitStates[2] = {NET_WAIT_NONE, NET_WAIT_NONE};

    // timeout 统一以毫秒累计，与两个 *TimeoutMs 配置项同单位
    const float pollTimeMs = (float)gConfigTlsPollingIntervalMs;
    float timeout = 0;

    while (rgTlsServerRun)
    {
        int eventsNumber = netWaitSetWait(waitSet, 2, 0, gConfigTlsPollingIntervalMs, waitFds, waitStates);
        if (eventsNumber == -1)
        {
            logOutputErrorConsole("tls Proxy: Failed to wait for events: " + std::string(netErrorString(netLastError())));
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

        // 水平触发：一次事件只做一次 SSL_read / SSL_write，
        // 剩余数据会再次触发通知，不需要靠 SSL_pending() 手工排空。
        for (int i = 0; i < 2; i++)
        {
            if (waitStates[i] == NET_WAIT_NONE)
            {
                continue;
            }

            SOCKET_T activeFd = waitFds[i];

            if (waitStates[i] == NET_WAIT_FAILED)
            {
                logOutputErrorConsole("tls Proxy: wait set reported failure on fd " + std::to_string((int)activeFd));
                isBreak = true;
            }
            else
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
                                SOCKET_T dstSocket = isAtoB ? bSocket : aSocket;
                                SOCKET_T writeFds[1] = {dstSocket};
                                int writeStates[1] = {NET_WAIT_NONE};

                                // 只在真实错误时中断；返回 0 是等待超时，
                                // 交给下面的累计 timeout 判定，避免一次 select 超时就把连接掐掉
                                int writeReady = netWaitSetWait(waitSet, 1, 1, gConfigSocketPollingIntervalMs, writeFds, writeStates);
                                if (writeReady == -1)
                                {
                                    logOutputErrorConsole("tls Proxy: bSsl write wait failed: " + std::string(netErrorString(netLastError())));
                                    isBreak = true;
                                    break;
                                }
                                if (writeStates[0] == NET_WAIT_FAILED)
                                {
                                    logOutputErrorConsole("tls Proxy: bSsl write wait reported failure");
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
                        int sys_errno = netLastError();
                        if (sys_errno == 0)
                        {
                            logOutputInfoConsole("tls Proxy: aSsl connection closed cleanly");
                        }
                        else if (netIsReset(sys_errno))
                        {
                            logOutputInfoConsole("tls Proxy: aSsl connection reset by peer");
                        }
                        else
                        {
                            logOutputErrorConsole("tls Proxy: aSsl read syscall error: " + std::string(netErrorString(sys_errno)));
                        }
                    }
                    else if (recvErrno == SSL_ERROR_ZERO_RETURN)
                        logOutputInfoConsole("tls Proxy: aSsl closed connection");
                    else
                        logOutputErrorConsole("tls Proxy: aSsl read failed code: " + std::to_string(recvErrno));
                    isBreak = true;
                }
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

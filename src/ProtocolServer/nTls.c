#include "nTls.h" // 根据实际情况包含头文件
SSL_CTX *createContext(bool isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    if (isServer)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        logOutputErrorConsoleCharString("Error: Unable to create SSL context");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
}

bool configureServerContext(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, gServerTlsCertFileChar) <= 0)
    {
        logOutputErrorConsoleCharString("Error: Unable to load certificate file");
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, gServerTlsKeyFileChar, SSL_FILETYPE_PEM) <= 0)
    {
        logOutputErrorConsoleCharString("Error: Unable to load private key file");
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool configureClientContext(SSL_CTX *ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // 先装 OpenSSL 自己的默认信任库（受 SSL_CERT_FILE / OPENSSLDIR 影响）。
    // 注意：这个函数"目录存在"就返回 1，哪怕目录里一张 CA 都没有 ——
    // Windows 上默认路径经常是空的，此时下面所有后端握手都会以
    // "certificate verify failed" 失败。所以它成功不代表信任库可用。
    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        // 拿不到信任库时 SSL_VERIFY_PEER 会让所有后端握手失败，
        // 与其让失败原因淹没在握手错误里，不如直接拒绝建连。
        logOutputErrorConsoleCharString("Error: Unable to load system certificate trust store, refusing to connect to backend without certificate verification");
        return false;
    }

    // 再叠加配置指定的 CA 文件（client.tls.cert）。是"追加"不是"替换"，
    // 所以配了自签 CA 之后公共 CA 依然能用。
    // 这是自签 / 内网 CA 后端唯一可用的入口：OpenSSL 的默认路径在很多
    // Windows 部署里是空的，靠它没法验任何东西。
    if (gClientTlsCertFileChar != NULL && gClientTlsCertFileChar[0] != '\0')
    {
        if (!SSL_CTX_load_verify_locations(ctx, gClientTlsCertFileChar, NULL))
        {
            char err[512];
            unsigned long e = ERR_get_error();
            char errBuf[256];
            ERR_error_string_n(e, errBuf, sizeof(errBuf));
            snprintf(err, sizeof(err),
                     "Error: Unable to load client.tls.cert '%s' - %s",
                     gClientTlsCertFileChar, errBuf);
            logOutputErrorConsoleCharString(err);
            ERR_print_errors_fp(stderr);
            return false;
        }
        // 成功不在这里打日志：configureClientContext 每条连接都会调一次，
        // 打日志会变成每连接一行。启动时 main.cpp 已经记过一次了。
    }

    return true;
}

static void listenSocketConnectIoNone(TlsSocketUpgradeCallback socketUpgradeTlsCallback, TlsClientCallback tlsCallback)
{
    if (socketUpgradeTlsCallback == NULL)
    {
        logOutputErrorConsoleCharString("Listen: socketCallback is NULL");
        return;
    }

    rgTlsServerRun = true;

    while (rgTlsServerRun)
    {
        struct sockaddr_in clientAddr;
        NET_SOCKLEN_T clientLen = sizeof(clientAddr);
        SOCKET_T clientFd = accept(rgTlsSocketServerFd, (struct sockaddr *)&clientAddr, &clientLen);

        if (netSocketValid(clientFd))
        {
            // 成功接受连接
            char clientIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
            int clientPort = ntohs(clientAddr.sin_port);
            SocketClientInfo clientInfo;
            memset(&clientInfo, 0, sizeof(clientInfo));
            clientInfo.fd = clientFd;
            clientInfo.addr = clientAddr;
            clientInfo.addr_len = clientLen;
            clientInfo.port = clientPort;
            strncpy(clientInfo.ip_str, clientIp, INET_ADDRSTRLEN - 1);
            clientInfo.ip_str[INET_ADDRSTRLEN - 1] = '\0';

            socketUpgradeTlsCallback(&clientInfo, tlsCallback);

            continue;
        }

        // accept 失败处理
        int acceptErr = netLastError();
        if (netIsWouldBlock(acceptErr))
        {
            continue;
        }

        // 其他错误处理
        if (netIsInterrupted(acceptErr))
        {
            // 被信号中断，继续循环
        }
        else if (netIsFdExhausted(acceptErr))
        {
            logOutputErrorConsoleCharString("Listen: too many open files, sleeping...");
        }
        else if (netIsAborted(acceptErr))
        {
            logOutputDebugConsoleCharString("Listen: connection aborted before accept");
        }
        else
        {
            char errMsg[256];
            snprintf(errMsg, sizeof(errMsg), "Listen: accept failed (errno=%d): %s",
                     acceptErr, netErrorString(acceptErr));
            logOutputErrorConsoleCharString(errMsg);
        }
    }
}

static int connectTlsSocketServer(SocketClientInfo *clientInfo, const char *host, int port)
{
    logOutputDebugConsoleCharString("Connect: start connect to socket server");

    if (clientInfo == NULL)
    {
        logOutputErrorConsoleCharString("Connect: client info is null");
        return -1;
    }
    if (host == NULL || host[0] == '\0')
    {
        logOutputErrorConsoleCharString("Connect: client host is null or empty");
        return -1;
    }
    if (port <= 0 || port > 65535)
    {
        char err[128];
        snprintf(err, sizeof(err), "Connect: invalid port %d", port);
        logOutputErrorConsoleCharString(err);
        return -1;
    }

    SOCKET_T sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (!netSocketValid(sockFd))
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Connect: socket() failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        return -1;
    }
    logOutputDebugConsoleCharString("Connect: socket() success");

    // 构建服务器地址
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)port);

    if (strcmp(host, "0.0.0.0") == 0 || strcmp(host, "*") == 0)
    {
        // connect 语义上 0.0.0.0 就是本机回环，所以这里要填 LOOPBACK 而不是 INADDR_ANY。
        // Linux 内核会把 connect 到 0.0.0.0 按 127.0.0.1 处理；Windows 不认，
        // 会直接返回 WSAEADDRNOTAVAIL（"请求的地址无效"）。这里显式填 127.0.0.1 让两边一致。
        // 注意：上面 initTlsServer 里的 bind 路径仍然用 INADDR_ANY，那是"监听所有网卡"，不要一起改。
        serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        logOutputDebugConsoleCharString("Connect: connecting to 0.0.0.0, treated as localhost");
    }
    else if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0)
    {
        serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        logOutputDebugConsoleCharString("Connect: connecting to localhost");
    }
    else if (!netResolveIpv4(host, &serverAddr))
    {
        char err[256];
        snprintf(err, sizeof(err), "Connect: cannot resolve hostname '%s'", host);
        logOutputErrorConsoleCharString(err);
        netSocketClose(sockFd);
        return -1;
    }

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serverAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    // 端口从 serverAddr 里取，不打印 port 变量：否则实际结构体里的端口被改错了也看不出来
    snprintf(msg, sizeof(msg), "Connect: target IP %s, port %d", ipStr, ntohs(serverAddr.sin_port));
    logOutputDebugConsoleCharString(msg);

    if (gConfigTlsSocketIoUseMode != CONNECT_USE_IO_NONE)
    {
        logOutputErrorConsoleCharString("Connect: tls socket ioUseMode is not supported yet, only 'none' is implemented");
        netSocketClose(sockFd);
        return -1;
    }

    // 走到这里 ioUseMode 必然是 none（上面已拦截），整段是阻塞模式实现
    {
        if (gConfigTlsConnectTimeoutMs > 0)
        {
            // 阻塞模式下设置收发超时
            if (netSetSendTimeoutMs(sockFd, gConfigTlsConnectTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Connect: set socket send timeout failed");
                netSocketClose(sockFd);
                return -1;
            }

            if (netSetRecvTimeoutMs(sockFd, gConfigTlsConnectTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Connect: set socket recv timeout failed");
                netSocketClose(sockFd);
                return -1;
            }
            logOutputDebugConsoleCharString("Connect: set socket timeout");
        }

        bool isBreak = false;
        while (!isBreak)
        {
            int connectRet = connect(sockFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
            if (connectRet == 0)
            {
                logOutputDebugConsoleCharString("Connect: connection established immediately");
                break;
            }
            else if (netIsInProgress(netLastError()))
            {
                continue;
            }
            else
            {
                isBreak = true;
            }
        }

        if (isBreak)
        {
            char errMsg[256];
            snprintf(errMsg, sizeof(errMsg), "Connect: connect() failed - %s", netErrorString(netLastError()));
            logOutputErrorConsoleCharString(errMsg);
            netSocketClose(sockFd);
            return -1;
        }
    }

    // 获取本地地址信息
    struct sockaddr_in localAddr;
    NET_SOCKLEN_T localLen = sizeof(localAddr);
    if (getsockname(sockFd, (struct sockaddr *)&localAddr, &localLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getsockname failed");
        netSocketClose(sockFd);
        return -1;
    }

    // 获取对端地址信息（可选）
    struct sockaddr_in peerAddr;
    NET_SOCKLEN_T peerLen = sizeof(peerAddr);
    if (getpeername(sockFd, (struct sockaddr *)&peerAddr, &peerLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getpeername failed");
        netSocketClose(sockFd);
        return -1;
    }

    // 填充 SocketClientInfo
    memset(clientInfo, 0, sizeof(SocketClientInfo));
    clientInfo->fd = sockFd;
    memcpy(&clientInfo->addr, &localAddr, sizeof(localAddr));
    clientInfo->addr_len = localLen;
    char localIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddr.sin_addr, localIpStr, sizeof(localIpStr));
    strncpy(clientInfo->ip_str, localIpStr, INET_ADDRSTRLEN - 1);
    clientInfo->ip_str[INET_ADDRSTRLEN - 1] = '\0';
    clientInfo->port = ntohs(localAddr.sin_port);

    logOutputInfoConsoleCharString("Connect to server success");
    return (int)sockFd;
}

static bool isValidTlsHost(const char *host)
{
    return host != NULL && host[0] != '\0' && strcmp(host, "0.0.0.0") != 0 && strcmp(host, "localhost") != 0;
}

void initTlsServer()
{
    if (gConfigTlsEnbale == false)
    {
        logOutputErrorConsoleCharString("Init: tls server is disabled");
        return;
    }

    if (rgTlsInit)
    {
        logOutputErrorConsoleCharString("Init: tls server is already init");
        return;
    }

    logOutputDebugConsoleCharString("Init: start init tls server");
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_LOAD_CONFIG, NULL);

    // 参数有效性检查
    if (gServerHostChar == NULL || gServerHostChar[0] == '\0')
    {
        logOutputErrorConsoleCharString("Init: socket server failed - server host is null or empty");
        return;
    }
    if (gServerPort <= 0 || gServerPort > 65535)
    {
        char err[128];
        snprintf(err, sizeof(err), "Init: socket server failed - invalid port: %d", gServerPort);
        logOutputErrorConsoleCharString(err);
        return;
    }
    int backlog = gServerSocketMaxBacklog > 0 ? gServerSocketMaxBacklog : 5;
    if (backlog != gServerSocketMaxBacklog)
    {
        char warn[128];
        snprintf(warn, sizeof(warn), "Init: invalid backlog %d, using default 5", gServerSocketMaxBacklog);
        logOutputWarnConsoleCharString(warn);
    }

    logOutputDebugConsoleCharString("Init: start init socket server");

    rgTlsSocketServerFd = socket(AF_INET, SOCK_STREAM, 0);
    if (!netSocketValid(rgTlsSocketServerFd))
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: socket server failed: socket() error - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(error_msg);
        return;
    }

    // 设置端口重用
    int opt = 1;
    if (setsockopt(rgTlsSocketServerFd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: setsockopt(SO_REUSEADDR) failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(error_msg);
        netSocketClose(rgTlsSocketServerFd);
        rgTlsSocketServerFd = SOCKET_INVALID;
        return;
    }
    logOutputDebugConsoleCharString("Init: SO_REUSEADDR set");

    // 绑定地址结构体
    memset(&rgTlsServerAddr, 0, sizeof(rgTlsServerAddr));
    rgTlsServerAddr.sin_family = AF_INET;

    // 解析主机地址：先看是不是特殊写法，再交给 getaddrinfo 统一处理
    if (strcmp(gServerHostChar, "0.0.0.0") == 0 || strcmp(gServerHostChar, "*") == 0)
    {
        rgTlsServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        logOutputDebugConsoleCharString("Init: binding to 0.0.0.0 (all interfaces)");
    }
    else if (strcmp(gServerHostChar, "127.0.0.1") == 0 || strcmp(gServerHostChar, "localhost") == 0)
    {
        rgTlsServerAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        logOutputDebugConsoleCharString("Init: binding to localhost");
    }
    else if (!netResolveIpv4(gServerHostChar, &rgTlsServerAddr))
    {
        char err[256];
        snprintf(err, sizeof(err), "Init: cannot resolve hostname '%s'", gServerHostChar);
        logOutputErrorConsoleCharString(err);
        netSocketClose(rgTlsSocketServerFd);
        rgTlsSocketServerFd = SOCKET_INVALID;
        return;
    }

    // 输出最终绑定的 IP
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rgTlsServerAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    snprintf(msg, sizeof(msg), "Init: binding to IP %s, port %d", ipStr, gServerPort);
    logOutputDebugConsoleCharString(msg);

    // 绑定端口
    rgTlsServerAddr.sin_port = htons((u_short)gServerPort);
    if (bind(rgTlsSocketServerFd, (struct sockaddr *)&rgTlsServerAddr, sizeof(rgTlsServerAddr)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: bind(%s:%d) failed - %s", ipStr, gServerPort, netErrorString(netLastError()));
        logOutputErrorConsoleCharString(error_msg);
        netSocketClose(rgTlsSocketServerFd);
        rgTlsSocketServerFd = SOCKET_INVALID;
        return;
    }
    logOutputDebugConsoleCharString("Init: bind success");

    // 监听
    if (listen(rgTlsSocketServerFd, backlog) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: listen() failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(error_msg);
        netSocketClose(rgTlsSocketServerFd);
        rgTlsSocketServerFd = SOCKET_INVALID;
        return; // 注意：此时不设置 rgSocketInit = true
    }
    logOutputDebugConsoleCharString("Init: listen success");

    rgTlsInit = true;

    logOutputDebugConsoleCharString("Init: tls socket server initialized successfully");
}

void listenTlsServer(TlsSocketUpgradeCallback socketUpgradeTlsCallback, TlsClientCallback tlsCallback)
{
    logOutputDebugConsoleCharString("Listen: start tls listen socket server");

    if (!netSocketValid(rgTlsSocketServerFd) || rgTlsInit == false)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: tls server not init");
        return;
    }

    if (socketUpgradeTlsCallback == NULL)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: socketCallback is null");
        return;
    }

    if (tlsCallback == NULL)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: tlsCallback is null");
        return;
    }

    if (gConfigTlsSocketIoUseMode != CONNECT_USE_IO_NONE)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: tls socket ioUseMode is not supported yet, only 'none' is implemented");
        return;
    }

    // 走到这里 ioUseMode 必然是 none（上面已拦截），整段是阻塞模式实现
    {
        if (gConfigTlsAcceptTimeoutMs > 0)
        {
            if (netSetSendTimeoutMs(rgTlsSocketServerFd, gConfigTlsAcceptTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Listen: set listen socket send timeout failed");
                netSocketClose(rgTlsSocketServerFd);
                rgTlsSocketServerFd = SOCKET_INVALID;
                return;
            }

            if (netSetRecvTimeoutMs(rgTlsSocketServerFd, gConfigTlsAcceptTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Listen: set listen socket recv timeout failed");
                netSocketClose(rgTlsSocketServerFd);
                rgTlsSocketServerFd = SOCKET_INVALID;
                return;
            }
        }
        listenSocketConnectIoNone(socketUpgradeTlsCallback, tlsCallback);
    }
}

void closeTlsServer()
{
    logOutputInfoConsoleCharString("Shutting down TLS Server...");
    rgTlsServerRun = false;
    // 必须真的关掉监听 fd：accept 循环阻塞在 accept() 上，仅置标志位无法唤醒它，
    // 后续线程池 shutdown() 里的 join() 会永久阻塞。shutdown() 用于唤醒阻塞的 accept。
    if (netSocketValid(rgTlsSocketServerFd))
    {
        netShutdownBoth(rgTlsSocketServerFd);
        netSocketClose(rgTlsSocketServerFd);
        rgTlsSocketServerFd = SOCKET_INVALID;
    }
    logOutputInfoConsoleCharString("TLS Server shut down.");
}

int connectTlsServer(TlsClientInfo *clientInfo, const char *sni, const char *host, int port)
{
    if (!clientInfo)
    {
        logOutputErrorConsoleCharString("connectTlsServer: Invalid client_info pointer");
        return -1;
    }

    memset(clientInfo, 0, sizeof(TlsClientInfo));

    SocketClientInfo socketInfo = {0};
    if (connectTlsSocketServer(&socketInfo, host, port) < 0 || !netSocketValid(socketInfo.fd))
    {
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer failed");
        return -1;
    }

    SSL_CTX *ctx = createContext(false);
    if (!ctx)
    {
        logOutputErrorConsoleCharString("connectTlsServer: createContext failed");
        netSocketClose(socketInfo.fd);
        return -1;
    }
    if (configureClientContext(ctx) == false)
    {
        logOutputErrorConsoleCharString("connectTlsServer: configureClientContext failed");
        SSL_CTX_free(ctx);
        netSocketClose(socketInfo.fd);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        logOutputErrorConsoleCharString("connectTlsServer: SSL_new failed");
        SSL_CTX_free(ctx);
        netSocketClose(socketInfo.fd);
        return -1;
    }
    // SSL_set_fd 的形参是 int：OpenSSL 在所有平台都用 int 接 fd。
    // Windows 的 SOCKET 是 64 位句柄，这里必须显式收窄 —— 实际句柄值远小于 INT_MAX。
    SSL_set_fd(ssl, (int)socketInfo.fd);

    // SNI 与证书主机名校验：配置的 sni 被 isValidTlsHost 判为无效时必须告警，
    // 否则主机名校验会在无任何提示的情况下静默失效。
    if (gClientTlsSniChar != NULL && gClientTlsSniChar[0] != '\0' && !isValidTlsHost(gClientTlsSniChar))
    {
        logOutputWarnConsoleCharString("Warning: client.tls.sni is set to an address that cannot be used as SNI/hostname, backend certificate hostname verification will be disabled");
    }

    if (isValidTlsHost(sni))
    {
        SSL_set_tlsext_host_name(ssl, sni);
    }
    else if (gClientTlsSniChar == NULL || gClientTlsSniChar[0] == '\0')
    {
        logOutputWarnConsoleCharString("Warning: no usable SNI for backend, backend certificate hostname verification will be disabled");
    }

    if (isValidTlsHost(gClientTlsSniChar))
    {
        SSL_set1_host(ssl, gClientTlsSniChar);
    }
    else if (isValidTlsHost(sni))
    {
        SSL_set1_host(ssl, sni);
    }

    if (gConfigTlsSocketIoUseMode != CONNECT_USE_IO_NONE)
    {
        logOutputErrorConsoleCharString("Connect: tls socket ioUseMode is not supported yet, only 'none' is implemented");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        netSocketClose(socketInfo.fd);
        return -1;
    }

    // 走到这里 ioUseMode 必然是 none（上面已拦截），整段是阻塞握手实现
    {
        int sslConnect = 0;
        int sslConnErr = SSL_ERROR_NONE;

        while (true)
        {
            sslConnect = SSL_connect(ssl);
            sslConnErr = SSL_ERROR_NONE;
            if (sslConnect == 1)
            {
                break;
            }
            sslConnErr = SSL_get_error(ssl, sslConnect);

            if (sslConnErr == SSL_ERROR_WANT_READ || sslConnErr == SSL_ERROR_WANT_WRITE)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "SSL_connect select error: %s - %d", netErrorString(netLastError()), netLastError());
                logOutputErrorConsoleCharString(msg);
                break;
            }
            else if (sslConnErr == SSL_ERROR_SYSCALL)
            {
                // 检查系统调用的errno是否代表超时
                int syscallErr = netLastError();
                if (syscallErr == 0)
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "SSL_connect syscall closed: no error reported");
                    logOutputErrorConsoleCharString(msg);
                }
                else if (netIsTimeout(syscallErr) || netIsWouldBlock(syscallErr))
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "SSL_connect syscall timeout: errno=%d", syscallErr);
                    logOutputErrorConsoleCharString(msg);
                }
                else
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "SSL_connect syscall error: errno=%d", syscallErr);
                    logOutputErrorConsoleCharString(msg);
                }
                break;
            }
            else
            {
                char msg[128];
                snprintf(msg, sizeof(msg), "SSL_connect fatal SSL error: %d", sslConnErr);
                logOutputErrorConsoleCharString(msg);
                break;
            }
        }

        // 握手成功时 sslConnErr 保持 SSL_ERROR_NONE；任何失败路径都由 SSL_get_error 填入真实错误码
        if (sslConnErr != SSL_ERROR_NONE)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char error_string[512];
            snprintf(error_string, sizeof(error_string), "connectTlsServer: SSL_connect failed - %s", err_buf);
            logOutputErrorConsoleCharString(error_string);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            netSocketClose(socketInfo.fd);
            return -1;
        }
    }

    clientInfo->fd = socketInfo.fd;
    clientInfo->ssl_ctx = ctx;
    clientInfo->ssl = ssl;
    memcpy(&clientInfo->addr, &socketInfo.addr, sizeof(socketInfo.addr));
    clientInfo->addr_len = socketInfo.addr_len;
    strncpy(clientInfo->ip_str, socketInfo.ip_str, INET_ADDRSTRLEN);
    clientInfo->port = socketInfo.port;

    return 0;
}

void closeTlsResource()
{
    logOutputInfoConsoleCharString("Cleaning up all TLS resources...");
    rgTlsServerRun = false;
    OPENSSL_cleanup();
    rgTlsInit = false;
    logOutputInfoConsoleCharString("All TLS resources cleaned up.");
}

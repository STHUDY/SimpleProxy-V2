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

    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        logOutputWarnConsoleCharString("Warning: Unable to load system certificate trust store, backend certificate verification will be disabled");
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
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(rgTlsSocketServerFd, (struct sockaddr *)&clientAddr, &clientLen);

        if (clientFd >= 0)
        {
            // 成功接受连接
            char clientIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
            int clientPort = ntohs(clientAddr.sin_port);
            SocketClientInfo clientInfo = {
                .fd = clientFd,
                .addr = clientAddr,
                .addr_len = clientLen,
                .port = clientPort};
            strncpy(clientInfo.ip_str, clientIp, INET_ADDRSTRLEN - 1);
            clientInfo.ip_str[INET_ADDRSTRLEN - 1] = '\0';

            // upgradeSocketToTlsConnect(clientFd, &clientInfo, socketCallback, tlsCallback);

            socketUpgradeTlsCallback(&clientInfo, tlsCallback);

            continue;
        }

        // accept 失败处理
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            continue;
        }

        // 其他错误处理
        switch (errno)
        {
        case EINTR:
            // 被信号中断，继续循环
            break;
        case EMFILE:
            logOutputErrorConsoleCharString("Listen: too many open files, sleeping...");
            break;
        case ECONNABORTED:
            logOutputDebugConsoleCharString("Listen: connection aborted before accept");
            break;
        default:
        {
            char errMsg[256];
            snprintf(errMsg, sizeof(errMsg), "Listen: accept failed (errno=%d): %s",
                     errno, strerror(errno));
            logOutputErrorConsoleCharString(errMsg);
            break;
        }
        }
    }
}

static int connectTlsSocketServer(SocketClientInfo *clientInfo)
{
    logOutputDebugConsoleCharString("Connect: start connect to socket server");

    if (clientInfo == NULL)
    {
        logOutputErrorConsoleCharString("Connect: client info is null");
        return -1;
    }
    if (gClientHostChar == NULL || gClientHostChar[0] == '\0')
    {
        logOutputErrorConsoleCharString("Connect: client host is null or empty");
        return -1;
    }
    if (gClientPort <= 0 || gClientPort > 65535)
    {
        char err[128];
        snprintf(err, sizeof(err), "Connect: invalid port %d", gClientPort);
        logOutputErrorConsoleCharString(err);
        return -1;
    }

    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0)
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Connect: socket() failed - %s", strerror(errno));
        logOutputErrorConsoleCharString(errorMsg);
        return -1;
    }
    logOutputDebugConsoleCharString("Connect: socket() success");

    // 构建服务器地址
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(gClientPort);

    if (strcmp(gClientHostChar, "0.0.0.0") == 0 || strcmp(gClientHostChar, "*") == 0)
    {
        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        logOutputDebugConsoleCharString("Connect: connecting to 0.0.0.0 (any)");
    }
    else if (strcmp(gClientHostChar, "127.0.0.1") == 0 || strcmp(gClientHostChar, "localhost") == 0)
    {
        serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        logOutputDebugConsoleCharString("Connect: connecting to localhost");
    }
    else
    {
        if (inet_pton(AF_INET, gClientHostChar, &serverAddr.sin_addr) <= 0)
        {
            struct hostent *hostent = gethostbyname(gClientHostChar);
            if (hostent == NULL)
            {
                char err[256];
                snprintf(err, sizeof(err), "Connect: cannot resolve hostname '%s'", gClientHostChar);
                logOutputErrorConsoleCharString(err);
                close(sockFd);
                return -1;
            }
            memcpy(&serverAddr.sin_addr, hostent->h_addr_list[0], hostent->h_length);
            logOutputDebugConsoleCharString("Connect: hostname resolved");
        }
    }

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serverAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    snprintf(msg, sizeof(msg), "Connect: target IP %s, port %d", ipStr, gClientPort);
    logOutputDebugConsoleCharString(msg);

    if (gConfigTlsSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        if (gConfigTlsConnectTimeoutMs > 0)
        {
            // 阻塞模式下设置收发超时
            struct timeval tv;
            tv.tv_sec = gConfigTlsConnectTimeoutMs / 1000;
            tv.tv_usec = (gConfigTlsConnectTimeoutMs % 1000) * 1000;
            if (setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
            {
                perror("Connect: setsockopt SO_SNDTIMEO");
                close(sockFd);
                return -1;
            }
            if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            {
                perror("Connect: setsockopt SO_RCVTIMEO");
                close(sockFd);
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
            else if (errno == EINPROGRESS)
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
            snprintf(errMsg, sizeof(errMsg), "Connect: connect() failed - %s", strerror(errno));
            logOutputErrorConsoleCharString(errMsg);
            close(sockFd);
            return -1;
        }
    }

    // 获取本地地址信息
    struct sockaddr_in localAddr;
    socklen_t localLen = sizeof(localAddr);
    if (getsockname(sockFd, (struct sockaddr *)&localAddr, &localLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getsockname failed");
        close(sockFd);
        return -1;
    }

    // 获取对端地址信息（可选）
    struct sockaddr_in peerAddr;
    socklen_t peerLen = sizeof(peerAddr);
    if (getpeername(sockFd, (struct sockaddr *)&peerAddr, &peerLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getpeername failed");
        close(sockFd);
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
    return sockFd;
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
    if (rgTlsSocketServerFd < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: socket server failed: socket() error - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        return;
    }

    // 设置端口重用
    int opt = 1;
    if (setsockopt(rgTlsSocketServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: setsockopt(SO_REUSEADDR) failed - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        close(rgTlsSocketServerFd);
        rgTlsSocketServerFd = -1;
        return;
    }
    logOutputDebugConsoleCharString("Init: SO_REUSEADDR set");

    // 绑定地址结构体
    memset(&rgTlsServerAddr, 0, sizeof(rgTlsServerAddr));
    rgTlsServerAddr.sin_family = AF_INET;

    // 解析主机地址
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
    else
    {
        // 尝试解析为 IPv4 点分十进制
        if (inet_pton(AF_INET, gServerHostChar, &rgTlsServerAddr.sin_addr) <= 0)
        {
            // 不是 IP 地址，尝试域名解析
            struct hostent *hostent = gethostbyname(gServerHostChar);
            if (hostent == NULL)
            {
                char err[256];
                snprintf(err, sizeof(err), "Init: cannot resolve hostname '%s'", gServerHostChar);
                logOutputErrorConsoleCharString(err);
                close(rgTlsSocketServerFd);
                rgTlsSocketServerFd = -1;
                return;
            }
            // 复制第一个 IPv4 地址
            memcpy(&rgTlsServerAddr.sin_addr, hostent->h_addr_list[0], hostent->h_length);
            logOutputDebugConsoleCharString("Init: hostname resolved");
        }
        // inet_pton 成功则地址已填充
    }

    // 输出最终绑定的 IP
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rgTlsServerAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    snprintf(msg, sizeof(msg), "Init: binding to IP %s, port %d", ipStr, gServerPort);
    logOutputDebugConsoleCharString(msg);

    // 绑定端口
    rgTlsServerAddr.sin_port = htons(gServerPort);
    if (bind(rgTlsSocketServerFd, (struct sockaddr *)&rgTlsServerAddr, sizeof(rgTlsServerAddr)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: bind(%s:%d) failed - %s", ipStr, gServerPort, strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        close(rgTlsSocketServerFd);
        rgTlsSocketServerFd = -1;
        return;
    }
    logOutputDebugConsoleCharString("Init: bind success");

    // 监听
    if (listen(rgTlsSocketServerFd, backlog) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init: listen() failed - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        close(rgTlsSocketServerFd);
        rgTlsSocketServerFd = -1;
        return; // 注意：此时不设置 rgSocketInit = true
    }
    logOutputDebugConsoleCharString("Init: listen success");

    rgTlsInit = true;

    logOutputDebugConsoleCharString("Init: tls socket server initialized successfully");
}

void listenTlsServer(TlsSocketUpgradeCallback socketUpgradeTlsCallback, TlsClientCallback tlsCallback)
{
    logOutputDebugConsoleCharString("Listen: start tls listen socket server");

    if (rgTlsSocketServerFd < 0 || rgTlsInit == false)
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

    if (gConfigTlsSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        if (gConfigTlsAcceptTimeoutMs > 0)
        {
            struct timeval tv;
            tv.tv_sec = gConfigTlsAcceptTimeoutMs / 1000;
            tv.tv_usec = (gConfigTlsAcceptTimeoutMs % 1000) * 1000;

            if (setsockopt(rgTlsSocketServerFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
            {
                perror("Listen: setsockopt SO_SNDTIMEO");
                close(rgTlsSocketServerFd);
                return;
            }

            if (setsockopt(rgTlsSocketServerFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            {
                perror("Listen: setsockopt SO_RCVTIMEO");
                close(rgTlsSocketServerFd);
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
    logOutputInfoConsoleCharString("TLS Server shut down.");
}

int connectTlsServer(TlsClientInfo *clientInfo, const char *sni)
{
    if (!clientInfo)
    {
        logOutputErrorConsoleCharString("connectTlsServer: Invalid client_info pointer");
        return -1;
    }

    memset(clientInfo, 0, sizeof(TlsClientInfo));

    SocketClientInfo socketInfo = {0};
    if (connectTlsSocketServer(&socketInfo) < 0 || socketInfo.fd < 0)
    {
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer failed");
        return -1;
    }

    SSL_CTX *ctx = createContext(false);
    if (!ctx)
    {
        logOutputErrorConsoleCharString("connectTlsServer: createContext failed");
        close(socketInfo.fd);
        return -1;
    }
    if (configureClientContext(ctx) == false)
    {
        logOutputErrorConsoleCharString("connectTlsServer: configureClientContext failed");
        SSL_CTX_free(ctx);
        close(socketInfo.fd);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        logOutputErrorConsoleCharString("connectTlsServer: SSL_new failed");
        SSL_CTX_free(ctx);
        close(socketInfo.fd);
        return -1;
    }
    SSL_set_fd(ssl, socketInfo.fd);

    if (isValidTlsHost(sni))
    {
        SSL_set_tlsext_host_name(ssl, sni);
    }

    if (isValidTlsHost(gClientTlsSniChar))
    {
        SSL_set1_host(ssl, gClientTlsSniChar);
    }
    else if (isValidTlsHost(sni))
    {
        SSL_set1_host(ssl, sni);
    }

    if (gConfigTlsSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        int sslConnect = 0;
        int sslConnErr = 0;

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
                snprintf(msg, sizeof(msg), "SSL_accept select error: %s - %d", strerror(errno), errno);
                logOutputErrorConsoleCharString(msg);
                break;
            }
            else if (sslConnErr == SSL_ERROR_SYSCALL)
            {
                // 检查系统调用的errno是否代表超时
                if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "SSL_accept syscall timeout: errno=%d", errno);
                    logOutputErrorConsoleCharString(msg);
                }
                else
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "SSL_accept syscall error: errno=%d", errno);
                    logOutputErrorConsoleCharString(msg);
                }
                break;
            }
            else
            {
                char msg[128];
                snprintf(msg, sizeof(msg), "SSL_accept fatal SSL error: %d", sslConnErr);
                logOutputErrorConsoleCharString(msg);
                break;
            }
        }

        if (sslConnErr = SSL_ERROR_NONE)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char error_string[512];
            snprintf(error_string, sizeof(error_string), "connectTlsServer: SSL_connect failed - %s", err_buf);
            logOutputErrorConsoleCharString(error_string);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(socketInfo.fd);
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

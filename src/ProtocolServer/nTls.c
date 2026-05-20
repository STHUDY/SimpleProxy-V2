#include "nTls.h" // 根据实际情况包含头文件

static SSL_CTX *createContext(bool isServer)
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

static bool configureServerContext(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, tlsCertFileChar) <= 0)
    {
        logOutputErrorConsoleCharString("Error: Unable to load certificate file");
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, tlsKeyFileChar, SSL_FILETYPE_PEM) <= 0)
    {
        logOutputErrorConsoleCharString("Error: Unable to load private key file");
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

static bool configureClientContext(SSL_CTX *ctx)
{
    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        logOutputWarnConsoleCharString("Warning: Unable to load system certificate trust store, backend certificate verification will be disabled");
    }
    return true;
}

static bool isValidTlsHost(const char *host)
{
    return host != NULL && host[0] != '\0' && strcmp(host, "0.0.0.0") != 0 && strcmp(host, "localhost") != 0;
}

void initTlsServer()
{
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_LOAD_CONFIG, NULL);

    signal(SIGPIPE, SIG_IGN);
    logOutputInfoConsoleCharString("Init tls server");

    logOutputDebugConsoleCharString("Init tls server context success");

    logOutputDebugConsoleCharString("Init tls socket server");

    tlsSocketServerFd = socket(AF_INET, SOCK_STREAM, 0);
    if (tlsSocketServerFd < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init socket server failed: socket() error - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(tlsSocketServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init socket server failed: setsockopt(SO_REUSEADDR) error - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        exit(EXIT_FAILURE);
    }
    memset(&tlsServerAddr, 0, sizeof(tlsServerAddr));
    tlsServerAddr.sin_family = AF_INET;
    tlsServerAddr.sin_port = htons(serverPort); // 设置端口

    logOutputDebugConsoleCharString("Init tls socket server bind hostent");
    struct hostent *hostent;
    if (strcmp(serverHostChar, "0.0.0.0") == 0 || strcmp(serverHostChar, "") == 0)
    {
        tlsServerAddr.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    }
    else if (strcmp(serverHostChar, "localhost") == 0)
    {
        if (inet_pton(AF_INET, "127.0.0.1", &tlsServerAddr.sin_addr) <= 0)
        {
            logOutputErrorConsoleCharString("Init socket server have a mistake: localhost error");
            exit(EXIT_FAILURE);
        }
    }
    else if (inet_pton(AF_INET, serverHostChar, &tlsServerAddr.sin_addr) < 0)
    {
        hostent = gethostbyname(serverHostChar);
        if (hostent == NULL)
        {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Init tls socket server failed: cannot resolve host '%s'", serverHostChar);
            logOutputErrorConsoleCharString(error_msg);
            exit(EXIT_FAILURE);
        }
        if (hostent->h_addrtype != AF_INET)
        {
            logOutputErrorConsoleCharString("Init tls socket server have a mistake: host can't bind not ipv4");
            exit(EXIT_FAILURE);
        }
        // 复制第一个IP地址
        memcpy(&tlsServerAddr.sin_addr, hostent->h_addr_list[0], sizeof(struct in_addr));
    }

    if (bind(tlsSocketServerFd, (struct sockaddr *)&tlsServerAddr, sizeof(tlsServerAddr)) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init tls socket server failed: bind() error on %s:%d - %s",
                 serverHostChar, serverPort, strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
        exit(EXIT_FAILURE);
    }

    if (listen(tlsSocketServerFd, serverSocketMaxBacklog) < 0)
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Init tls socket server failed: listen() error - %s", strerror(errno));
        logOutputErrorConsoleCharString(error_msg);
    }

    char success_msg[256];
    snprintf(success_msg, sizeof(success_msg), "Tls socket server initialized successfully on %s:%d", serverHostChar, serverPort);
    logOutputInfoConsoleCharString(success_msg);

    tlsInit = true;
}

void listenTlsServer(TlsClientCallback callback)
{
    logOutputDebugConsoleCharString("Listen tls server");
    if (tlsInit == false)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: tls server not init");
        return;
    }

    if (callback == NULL)
    {
        logOutputErrorConsoleCharString("Listen tls server have a mistake: callback is null");
        return;
    }

    TlsServerRun = true;

    if (TlsNoBlockConnect)
    {
        int flag = fcntl(tlsSocketServerFd, F_GETFL, 0);
        if (flag == -1)
        {
            logOutputErrorConsoleCharString("Listen tls server have a mistake: fcntl(F_GETFL) error");
            return;
        }

        flag |= O_NONBLOCK;
        if (fcntl(tlsSocketServerFd, F_SETFL, flag) == -1)
        {
            logOutputErrorConsoleCharString("Listen tls server have a mistake: fcntl(F_SETFL) error");
            return;
        }
    }

    clock_t start, end;

    while (TlsServerRun)
    {
        if (TlsNoBlockConnect)
        {
            start = clock();
        }

        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        int clientFd = accept(tlsSocketServerFd, (struct sockaddr *)&clientAddr, &clientAddrLen);

        if (TlsNoBlockConnect)
        {
            end = clock();
        }

        if (clientFd < 0)
        {
            switch (errno)
            {
            case EWOULDBLOCK:
                if (SocketNoBlockConnect)
                {
                    int timeCount = ((end - start) * 1000000) / CLOCKS_PER_SEC;
                    if (timeCount > PollingIntervalMs)
                        timeCount = PollingIntervalMs * 1000;

                    usleep(timeCount);
                }
                break;

            case EINTR:
                break;

            case EMFILE:
            case ENFILE:
                // 进程/系统 fd 用完（严重错误）
                logOutputErrorConsoleCharString("Too many open files - system resource exhausted");
                usleep(PollingIntervalMs * 1000); // 休眠一下避免死循环
                break;

            case ECONNABORTED:
                // 客户端在三次握手后立即断开
                logOutputDebugConsoleCharString("Client connection aborted before accept completed");
                break;

            default:
                // 其它未知错误
                {
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), "accept() failed with errno %d: %s", errno, strerror(errno));
                    logOutputErrorConsoleCharString(error_msg);
                }
                break;
            }

            continue;
        }

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
        clientIp[INET_ADDRSTRLEN - 1] = '\0';
        int clientPort = ntohs(clientAddr.sin_port);

        SSL_CTX *ctx = createContext(true);
        configureServerContext(ctx);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientFd);
        int sslAccept = 0;
        int sslConnErr = 0;

        while (TlsServerRun)
        {
            if (TlsNoBlock)
            {
                start = clock();
            }

            sslAccept = SSL_accept(ssl);
            sslConnErr = SSL_ERROR_NONE;

            if (sslAccept == 1)
            {
                break;
            }

            sslConnErr = SSL_get_error(ssl, sslAccept);

            if (sslConnErr == SSL_ERROR_WANT_READ || sslConnErr == SSL_ERROR_WANT_WRITE)
            {
                int timeCount = ((end - start) * 1000000) / CLOCKS_PER_SEC;
                if (timeCount > PollingIntervalMs)
                    timeCount = PollingIntervalMs * 1000;

                usleep(timeCount);
                continue;
            }
            else
            {
                break;
            }

            if (TlsNoBlock)
            {
                end = clock();
            }
        }

        if (sslConnErr != SSL_ERROR_NONE)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char error_string[512];
            snprintf(error_string, sizeof(error_string), "SSL accept failed for client %s:%d - %s",
                     clientIp, clientPort, err_buf);
            logOutputErrorConsoleCharString(error_string);

            if (ssl)
            {
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            }

            if (clientFd >= 0)
                close(clientFd);

            continue;
        }

        TlsClientInfo clientInfo = {0};
        clientInfo.fd = clientFd;
        clientInfo.ssl_ctx = ctx;
        clientInfo.ssl = ssl;
        memcpy(&clientInfo.addr, &clientAddr, sizeof(clientAddr));
        clientInfo.addr_len = sizeof(clientAddr);
        strncpy(clientInfo.ip_str, clientIp, INET_ADDRSTRLEN);
        clientInfo.port = clientPort;

        if (callback)
        {
            callback(clientFd, &clientInfo);
        }
    }
}

void closeTlsServer()
{
    logOutputInfoConsoleCharString("Shutting down TLS Server...");
    TlsServerRun = false;
    logOutputInfoConsoleCharString("TLS Server shut down.");
}

int connectTlsServer(TlsClientInfo *client_info, const char *sni)
{
    if (!client_info)
    {
        logOutputErrorConsoleCharString("connectTlsServer: Invalid client_info pointer");
        return -1;
    }

    if (!tlsInit)
    {
        logOutputErrorConsoleCharString("connectTlsServer: TLS not initialized");
        return -1;
    }

    memset(client_info, 0, sizeof(TlsClientInfo));

    SocketClientInfo socketInfo = {0};
    if (connectSocketServer(&socketInfo) < 0 || socketInfo.fd < 0)
    {
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer failed");
        return -1;
    }

    SSL_CTX *ctx = createContext(false);
    configureClientContext(ctx);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socketInfo.fd);

    if (isValidTlsHost(sni))
    {
        SSL_set_tlsext_host_name(ssl, sni);
    }

    if (isValidTlsHost(tlsClientHostNameChar))
    {
        SSL_set1_host(ssl, tlsClientHostNameChar);
    }
    else if (isValidTlsHost(sni))
    {
        SSL_set1_host(ssl, sni);
    }

    if (SSL_connect(ssl) <= 0)
    {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        char error_string[512];
        snprintf(error_string, sizeof(error_string), "connectTlsServer: SSL_connect failed - %s", err_buf);
        logOutputErrorConsoleCharString(error_string);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socketInfo.fd);
        return -1;
    }

    client_info->fd = socketInfo.fd;
    client_info->ssl_ctx = ctx;
    client_info->ssl = ssl;
    memcpy(&client_info->addr, &socketInfo.addr, sizeof(socketInfo.addr));
    client_info->addr_len = socketInfo.addr_len;
    strncpy(client_info->ip_str, socketInfo.ip_str, INET_ADDRSTRLEN);
    client_info->port = socketInfo.port;

    return 0;
}

void closeTlsResource()
{
    logOutputInfoConsoleCharString("Cleaning up all TLS resources...");
    TlsServerRun = false;
    OPENSSL_cleanup();
    tlsInit = false;
    logOutputInfoConsoleCharString("All TLS resources cleaned up.");
}

#include "nSocket.h"

static void listenSocketConnectIoNone(SocketClientCallback callback)
{
    if (callback == NULL)
    {
        logOutputErrorConsoleCharString("Listen: callback is NULL");
        return;
    }

    rgSocketServerRun = true;

    while (rgSocketServerRun)
    {
        struct sockaddr_in clientAddr;
        NET_SOCKLEN_T clientLen = sizeof(clientAddr);
        SOCKET_T clientFd = accept(rgSocketServerFd, (struct sockaddr *)&clientAddr, &clientLen);

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

            callback(&clientInfo);
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

    logOutputInfoConsoleCharString("Listen: socket listening stopped (IO none mode)");
}

void initSocketServer()
{
    if (rgSocketInit)
    {
        logOutputDebugConsoleCharString("Init: socket server already init");
        return;
    }

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

    // 创建 socket
    rgSocketServerFd = socket(AF_INET, SOCK_STREAM, 0);
    if (!netSocketValid(rgSocketServerFd))
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Init: socket() failed: %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        return;
    }
    logOutputDebugConsoleCharString("Init: socket created");

    // 设置端口重用
    int opt = 1;
    if (setsockopt(rgSocketServerFd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0)
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Init: setsockopt(SO_REUSEADDR) failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        netSocketClose(rgSocketServerFd);
        rgSocketServerFd = SOCKET_INVALID;
        return;
    }
    logOutputDebugConsoleCharString("Init: SO_REUSEADDR set");

    // 绑定地址结构体
    memset(&rgSocketServerAddr, 0, sizeof(rgSocketServerAddr));
    rgSocketServerAddr.sin_family = AF_INET;

    // 解析主机地址：先看是不是特殊写法，再交给 getaddrinfo 统一处理
    if (strcmp(gServerHostChar, "0.0.0.0") == 0 || strcmp(gServerHostChar, "*") == 0)
    {
        rgSocketServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        logOutputDebugConsoleCharString("Init: binding to 0.0.0.0 (all interfaces)");
    }
    else if (strcmp(gServerHostChar, "127.0.0.1") == 0 || strcmp(gServerHostChar, "localhost") == 0)
    {
        rgSocketServerAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        logOutputDebugConsoleCharString("Init: binding to localhost");
    }
    else if (!netResolveIpv4(gServerHostChar, &rgSocketServerAddr))
    {
        char err[256];
        snprintf(err, sizeof(err), "Init: cannot resolve hostname '%s'", gServerHostChar);
        logOutputErrorConsoleCharString(err);
        netSocketClose(rgSocketServerFd);
        rgSocketServerFd = SOCKET_INVALID;
        return;
    }

    // 输出最终绑定的 IP
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rgSocketServerAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    snprintf(msg, sizeof(msg), "Init: binding to IP %s, port %d", ipStr, gServerPort);
    logOutputDebugConsoleCharString(msg);

    // 绑定端口
    rgSocketServerAddr.sin_port = htons((u_short)gServerPort);
    if (bind(rgSocketServerFd, (struct sockaddr *)&rgSocketServerAddr, sizeof(rgSocketServerAddr)) < 0)
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Init: bind(%s:%d) failed - %s", ipStr, gServerPort, netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        netSocketClose(rgSocketServerFd);
        rgSocketServerFd = SOCKET_INVALID;
        return;
    }
    logOutputDebugConsoleCharString("Init: bind success");

    // 监听
    if (listen(rgSocketServerFd, backlog) < 0)
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Init: listen() failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        netSocketClose(rgSocketServerFd);
        rgSocketServerFd = SOCKET_INVALID;
        return; // 注意：此时不设置 rgSocketInit = true
    }
    logOutputDebugConsoleCharString("Init: listen success");

    rgSocketInit = true;
    logOutputDebugConsoleCharString("Init: socket server initialized successfully");
}

void listenSocketServer(SocketClientCallback callback)
{
    logOutputDebugConsoleCharString("Listen: start listen socket server");

    // 检查服务器是否已启动
    if (!netSocketValid(rgSocketServerFd) || !rgSocketInit)
    {
        logOutputErrorConsoleCharString("Listen: server not started yet");
        return;
    }
    if (callback == NULL)
    {
        logOutputErrorConsoleCharString("Listen: callback function cannot be NULL");
        return;
    }

    if (gConfigSocketIoUseMode == CONNECT_USE_IO_NONE)
    {
        if (gConfigSocketAcceptTimeoutMs > 0)
        {
            if (netSetSendTimeoutMs(rgSocketServerFd, gConfigSocketAcceptTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Listen: set listen socket send timeout failed");
                netSocketClose(rgSocketServerFd);
                rgSocketServerFd = SOCKET_INVALID;
                return;
            }

            if (netSetRecvTimeoutMs(rgSocketServerFd, gConfigSocketAcceptTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Listen: set listen socket recv timeout failed");
                netSocketClose(rgSocketServerFd);
                rgSocketServerFd = SOCKET_INVALID;
                return;
            }
        }
        listenSocketConnectIoNone(callback);
    }
    else
    {
        logOutputErrorConsoleCharString("Listen: socket ioUseMode is not supported yet, only 'none' is implemented");
        return;
    }

    logOutputInfoConsoleCharString("Listen: socket listening stopped");
}

void closeSocketServer()
{
    rgSocketServerRun = false;
    logOutputDebugConsoleCharString("Close: socket server");
    // shutdown 用于唤醒阻塞在 accept() 上的线程，单独 close 不可靠
    netShutdownBoth(rgSocketServerFd);
    netSocketClose(rgSocketServerFd);
    rgSocketServerFd = SOCKET_INVALID;
}

SOCKET_T connectSocketServer(SocketClientInfo *clientInfo, const char *host, int port)
{
    logOutputDebugConsoleCharString("Connect: start connect to socket server");

    if (clientInfo == NULL)
    {
        logOutputErrorConsoleCharString("Connect: client info is null");
        return SOCKET_INVALID;
    }
    if (host == NULL || host[0] == '\0')
    {
        logOutputErrorConsoleCharString("Connect: client host is null or empty");
        return SOCKET_INVALID;
    }
    if (port <= 0 || port > 65535)
    {
        char err[128];
        snprintf(err, sizeof(err), "Connect: invalid port %d", port);
        logOutputErrorConsoleCharString(err);
        return SOCKET_INVALID;
    }

    SOCKET_T sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (!netSocketValid(sockFd))
    {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Connect: socket() failed - %s", netErrorString(netLastError()));
        logOutputErrorConsoleCharString(errorMsg);
        return SOCKET_INVALID;
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
        // 注意：上面 initSocketServer 里的 bind 路径仍然用 INADDR_ANY，那是"监听所有网卡"，不要一起改。
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
        return SOCKET_INVALID;
    }

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serverAddr.sin_addr, ipStr, sizeof(ipStr));
    char msg[256];
    // 端口从 serverAddr 里取，不打印 port 变量：否则实际结构体里的端口被改错了也看不出来
    snprintf(msg, sizeof(msg), "Connect: target IP %s, port %d", ipStr, ntohs(serverAddr.sin_port));
    logOutputDebugConsoleCharString(msg);

    if (gConfigSocketIoUseMode != CONNECT_USE_IO_NONE)
    {
        logOutputErrorConsoleCharString("Connect: socket ioUseMode is not supported yet, only 'none' is implemented");
        netSocketClose(sockFd);
        return SOCKET_INVALID;
    }

    // 走到这里 ioUseMode 必然是 none（上面已拦截），整段是阻塞模式实现
    {
        if (gConfigSocketConnectTimeoutMs > 0)
        {
            // 阻塞模式下设置收发超时
            if (netSetSendTimeoutMs(sockFd, gConfigSocketConnectTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Connect: set socket send timeout failed");
                netSocketClose(sockFd);
                return SOCKET_INVALID;
            }

            if (netSetRecvTimeoutMs(sockFd, gConfigSocketConnectTimeoutMs) < 0)
            {
                logOutputErrorConsoleCharString("Connect: set socket recv timeout failed");
                netSocketClose(sockFd);
                return SOCKET_INVALID;
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
            return SOCKET_INVALID;
        }
    }

    // 获取本地地址信息
    struct sockaddr_in localAddr;
    NET_SOCKLEN_T localLen = sizeof(localAddr);
    if (getsockname(sockFd, (struct sockaddr *)&localAddr, &localLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getsockname failed");
        netSocketClose(sockFd);
        return SOCKET_INVALID;
    }

    // 获取对端地址信息（可选）
    struct sockaddr_in peerAddr;
    NET_SOCKLEN_T peerLen = sizeof(peerAddr);
    if (getpeername(sockFd, (struct sockaddr *)&peerAddr, &peerLen) < 0)
    {
        logOutputErrorConsoleCharString("Connect: getpeername failed");
        netSocketClose(sockFd);
        return SOCKET_INVALID;
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

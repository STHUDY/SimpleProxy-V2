#include "nSocket.h"

void initSocketServer()
{
    logOutputDebugConsoleCharString("Init socket server");
    socketServerFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketServerFd < 0)
    {
        logOutputErrorConsoleCharString("Init socket server have a mistake: socket error");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(socketServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        logOutputErrorConsoleCharString("Init socket server have a mistake: setsockopt error");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort); // 设置端口

    logOutputDebugConsoleCharString("Init socket server bind hostent");
    struct hostent *hostent;

    if (strcmp(serverHostChar, "0.0.0.0") == 0 || strcmp(serverHostChar, "") == 0)
    {
        serverAddr.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    }
    else if (strcmp(serverHostChar, "localhost") == 0)
    {
        if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) > 0)
        {
            logOutputErrorConsoleCharString("Init socket server have a mistake: localhost error");
            exit(EXIT_FAILURE);
        }
    }
    else if (inet_pton(AF_INET, serverHostChar, &serverAddr.sin_addr) < 0)
    {
        hostent = gethostbyname(serverHostChar);
        if (hostent == NULL)
        {
            logOutputErrorConsoleCharString("Init socket server have a mistake: host can't bind");
            exit(EXIT_FAILURE);
        }
        if (hostent->h_addrtype != AF_INET)
        {
            logOutputErrorConsoleCharString("Init socket server have a mistake: host can't bind not ipv4");
            exit(EXIT_FAILURE);
        }
        // 复制第一个IP地址
        memcpy(&serverAddr.sin_addr, hostent->h_addr_list[0], sizeof(struct in_addr));
    }

    if (bind(socketServerFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        logOutputErrorConsoleCharString("Init socket server have a mistake: bind error");
        exit(EXIT_FAILURE);
    }

    if (listen(socketServerFd, serverSocketMaxBacklog) < 0)
    {
        logOutputErrorConsoleCharString("Init socket server have a mistake: listen error");
    }

    logOutputDebugConsoleCharString("Init socket server success");
}

void listenSocketServer(SocketClientCallback callback)
{
    logOutputDebugConsoleCharString("Listen socket server");

    // 检查服务器是否已启动
    if (socketServerFd < 0)
    {
        logOutputErrorConsoleCharString("Server is not started yet");
        return;
    }

    // 检查回调函数是否为空
    if (callback == NULL)
    {
        logOutputErrorConsoleCharString("Callback function cannot be NULL");
        return;
    }

    // 设置服务器运行标志
    SocketServerRun = true;

    if (SocketNoBlockConnect)
    {
        int flags = fcntl(socketServerFd, F_GETFL, 0);
        if (flags == -1)
        {
            logOutputErrorConsoleCharString("Get socket block flags error");
            return;
        }

        flags |= O_NONBLOCK; // 设置 O_NONBLOCK 标志
        if (fcntl(socketServerFd, F_SETFL, flags) == -1)
        {
            logOutputErrorConsoleCharString("Set socket no block flags error");
            return;
        }
    }

    clock_t start, end;

    // 主监听循环
    while (SocketServerRun)
    {

        if (SocketNoBlockConnect)
        {
            start = clock();
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // 等待新的客户端连接
        int client_fd = accept(socketServerFd, (struct sockaddr *)&client_addr, &client_len);

        if (SocketNoBlockConnect)
        {
            end = clock();
        }

        if (client_fd < 0)
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
                continue;

            case EMFILE:
            case ENFILE:
                // 进程/系统 fd 用完（严重错误）
                logOutputErrorConsoleCharString("Too many open files");
                usleep(PollingIntervalMs * 1000); // 休眠一下避免死循环
                break;

            case ECONNABORTED:
                // 客户端在三次握手后立即断开
                logOutputDebugConsoleCharString("Client aborted before accept");
                break;

            default:
                // 其它未知错误
                logOutputErrorConsoleCharString("accept() failed");
                break;
            }

            continue;
        }

        char client_ip[INET_ADDRSTRLEN];

        // 获取客户端IP地址
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);

        SocketClientInfo client_info;
        memset(&client_info, 0, sizeof(client_info));
        client_info.fd = client_fd;
        memcpy(&client_info.addr, &client_addr, sizeof(client_addr));
        client_info.addr_len = client_len;
        strncpy(client_info.ip_str, client_ip, INET_ADDRSTRLEN);
        client_info.ip_str[INET_ADDRSTRLEN - 1] = '\0';
        client_info.port = client_port;

        callback(client_fd, &client_info);
    }

    logOutputInfoConsoleCharString("socket listening stopped");
}

void closeSocketServer()
{
    SocketServerRun = false;
    logOutputDebugConsoleCharString("Close socket server");
    shutdown(socketServerFd, SHUT_RDWR);
    close(socketServerFd);
}

int connectSocketServer(SocketClientInfo *client_info)
{
    logOutputDebugConsoleCharString("Connect to socket server");

    // 检查参数是否有效
    if (client_info == NULL)
    {
        logOutputErrorConsoleCharString("SocketClientInfo cannot be NULL");
        return -1;
    }

    if (clientHostChar == NULL)
    {
        logOutputErrorConsoleCharString("Client host not configured");
        return -1;
    }

    // 创建套接字
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        logOutputErrorConsoleCharString("Create socket error");
        return -1;
    }

    // 设置连接超时（如果启用了超时）
    if (ConnectTimeout > 0)
    {
        struct timeval timeout;
        timeout.tv_sec = ConnectTimeout;
        timeout.tv_usec = 0;

        if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            logOutputErrorConsoleCharString("Set send timeout error");
            close(sock_fd);
            return -1;
        }

        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            logOutputErrorConsoleCharString("Set receive timeout error");
            close(sock_fd);
            return -1;
        }
    }

    // 准备服务器地址结构
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(clientPort);

    // 解析服务器地址
    struct hostent *hostent = NULL;

    // 处理特殊地址
    if (strcmp(clientHostChar, "localhost") == 0)
    {
        if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
        {
            logOutputErrorConsoleCharString("Invalid localhost address");
            close(sock_fd);
            return -1;
        }
    }
    // 尝试作为IP地址解析
    else if (inet_pton(AF_INET, clientHostChar, &server_addr.sin_addr) <= 0)
    {
        // 如果失败，尝试作为主机名解析
        hostent = gethostbyname(clientHostChar);
        if (hostent == NULL)
        {
            logOutputErrorConsoleCharString("Cannot resolve host name");
            close(sock_fd);
            return -1;
        }

        if (hostent->h_addrtype != AF_INET)
        {
            logOutputErrorConsoleCharString("Host is not IPv4 address");
            close(sock_fd);
            return -1;
        }

        // 复制第一个IP地址
        memcpy(&server_addr.sin_addr, hostent->h_addr_list[0], sizeof(struct in_addr));
    }

    // 尝试连接到服务器
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        logOutputErrorConsoleCharString("Connect to server failed");
        close(sock_fd);
        return -1;
    }

    // 获取本地地址信息
    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(sock_fd, (struct sockaddr *)&local_addr, &local_len) < 0)
    {
        logOutputErrorConsoleCharString("Get local address failed");
        close(sock_fd);
        return -1;
    }

    // 获取对端地址信息
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    if (getpeername(sock_fd, (struct sockaddr *)&peer_addr, &peer_len) < 0)
    {
        logOutputErrorConsoleCharString("Get peer address failed");
        close(sock_fd);
        return -1;
    }

    // 填充SocketClientInfo结构体
    memset(client_info, 0, sizeof(SocketClientInfo));

    // 填充本地地址信息
    memcpy(&client_info->addr, &local_addr, sizeof(local_addr));
    client_info->addr_len = local_len;

    // 转换IP地址为字符串
    char local_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip_str, sizeof(local_ip_str));
    strncpy(client_info->ip_str, local_ip_str, INET_ADDRSTRLEN);

    // 获取本地端口号
    client_info->port = ntohs(local_addr.sin_port);

    // 可以额外保存服务器信息（如果需要）
    // char server_ip_str[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &server_addr.sin_addr, server_ip_str, sizeof(server_ip_str));

    logOutputInfoConsoleCharString("Connect to server success");

    client_info->fd = sock_fd;

    // 返回套接字描述符
    return sock_fd;
}
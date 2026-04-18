#include "Callback.hpp"

// 检测TLS ClientHello消息
static bool isTlsClientHello(const char *data, size_t len) {
    // TLS ClientHello的特征：
    // - 第1字节为0x16 (Handshake protocol)
    // - 第2-3字节为版本号 (0x0301 for TLS 1.0, 0x0302 for TLS 1.1, 0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
    // - 第4-5字节为记录长度
    if (len < 5) {
        return false;
    }
    
    // 检查是否为Handshake协议
    if ((unsigned char)data[0] != 0x16) {
        return false;
    }
    
    // 检查版本号 (必须是0x03xx)
    if ((unsigned char)data[1] != 0x03) {
        return false;
    }
    
    // 检查记录长度
    uint16_t record_len = ((unsigned char)data[3] << 8) | (unsigned char)data[4];
    if (record_len == 0 || record_len > 16384) { // TLS记录最大长度通常为16KB
        return false;
    }
    
    // 如果数据长度足够，检查Handshake类型 (ClientHello应该是0x01)
    if (len >= 6 && (unsigned char)data[5] == 0x01) {
        return true;
    }
    
    return false;
}

// 检测HTTP请求
static bool isHttpRequest(const char *data, size_t len) {
    if (len < 4) {
        return false;
    }
    
    // 检查是否以HTTP方法开头
    std::string data_str(data, std::min(len, (size_t)10));
    std::transform(data_str.begin(), data_str.end(), data_str.begin(), ::toupper);
    
    return (data_str.substr(0, 4) == "GET " || 
            data_str.substr(0, 5) == "POST " || 
            data_str.substr(0, 5) == "HEAD " || 
            data_str.substr(0, 4) == "PUT " || 
            data_str.substr(0, 7) == "DELETE " || 
            data_str.substr(0, 6) == "PATCH " || 
            data_str.substr(0, 5) == "TRACE " || 
            data_str.substr(0, 8) == "CONNECT " ||
            data_str.substr(0, 4) == "OPTIONS ");
}

static bool isIpAllowed(const std::string &ip_str)
{
    auto ban_it = std::find(banIpList.begin(), banIpList.end(), ip_str);
    if (ban_it != banIpList.end())
    {
        return false; // IP 被禁止
    }

    if (allowIpList.empty())
    {
        return true;
    }

    // 如果白名单不为空，只有在白名单中的 IP 才能访问
    auto allow_it = std::find(allowIpList.begin(), allowIpList.end(), ip_str);
    if (allow_it != allowIpList.end())
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

    if (!isIpAllowed(socketClientInfo->ip_str))
    {
        logOutputWarnConsole("Access denied: IP '" + std::string(socketClientInfo->ip_str) + "' is in the BAN list.");
        shutdown(socketClientInfo->fd, SHUT_RDWR);
        close(socketClientInfo->fd);
        return;
    }

    // 在非阻塞模式下设置socket为非阻塞以进行快速检测
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        logOutputErrorConsole("Failed to get socket flags for detection");
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        logOutputErrorConsole("Failed to set socket to non-blocking for detection");
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    char detect_buffer[1024];
    ssize_t bytes_read = recv(fd, detect_buffer, sizeof(detect_buffer), MSG_PEEK);
    
    // 恢复原始socket标志
    if (fcntl(fd, F_SETFL, flags) == -1) {
        logOutputErrorConsole("Failed to restore socket flags");
        // 继续处理，但记录警告
    }

    if (bytes_read > 0) {
        // 检测TLS ClientHello
        if (isTlsClientHello(detect_buffer, bytes_read)) {
            logOutputWarnConsole("Detected TLS ClientHello from IP '" + std::string(socketClientInfo->ip_str) + 
                               "', but server is running in plain socket mode. Connection rejected.");
            shutdown(fd, SHUT_RDWR);
            close(fd);
            return;
        }
        
        // 检测HTTP请求 (可能发送到HTTPS端口)
        if (isHttpRequest(detect_buffer, bytes_read)) {
            logOutputWarnConsole("Detected HTTP request from IP '" + std::string(socketClientInfo->ip_str) + 
                               "', but server is running in plain socket mode. Connection rejected.");
            shutdown(fd, SHUT_RDWR);
            close(fd);
            return;
        }
    } else if (bytes_read == 0) {
        // 客户端立即关闭连接
        logOutputInfoConsole("Client closed connection immediately: " + std::string(socketClientInfo->ip_str));
        close(fd);
        return;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logOutputErrorConsole("Error reading from client socket: " + std::string(strerror(errno)));
            close(fd);
            return;
        }
        // 如果是EAGAIN/EWOULDBLOCK，说明没有数据可读，继续正常处理
    }

    SocketClientInfo *aConnectInfo = new SocketClientInfo(*socketClientInfo);
    SocketClientInfo *bConnectInfo = new SocketClientInfo;

    if (connectSocketServer(bConnectInfo) < 0)
    {
        if (aConnectInfo->fd > 0)
        {
            shutdown(aConnectInfo->fd, SHUT_RDWR);
            close(aConnectInfo->fd);
        }

        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    logOutputInfoConsole("New connection from " + std::string(socketClientInfo->ip_str) + ":" + std::to_string(socketClientInfo->port));

    CallbackShareInfo *shareInfo = new CallbackShareInfo;
    shareInfo->init = false;
    shareInfo->timeout = 0;
    shareInfo->mutex = new std::mutex;
    shareInfo->close = false;

    threadPool.pushMission(socketProxyWorkerSingle, aConnectInfo, bConnectInfo, clientSocketBufferSize, shareInfo, std::string("client -> proxy -> server "));
    threadPool.pushMission(socketProxyWorkerSingle, bConnectInfo, aConnectInfo, serverSocketBufferSize, shareInfo, std::string("server -> proxy -> client "));
}

void socketListenerCallback()
{
    listenSocketServer(socketServerCallback);
}

void socketProxyWorkerSingle(SocketClientInfo *aConnectInfo, SocketClientInfo *bConnectInfo, size_t bufferSize, CallbackShareInfo *shareInfo, std::string headText)
{
    // 调用方必须保证socket有效

    std::mutex *mutex = shareInfo->mutex;

    int aSocket = aConnectInfo->fd;
    int bSocket = bConnectInfo->fd;

    char *buffer = new char[bufferSize];

    std::unique_lock<std::mutex> ulock(*mutex);

    const float PollTimeSeconds = (float)PollingIntervalMs / 1000.0f;

    fd_set readfds, writefds, exceptfds;

    if (shareInfo->init == false && SocketEnableSync == false)
    {
        fcntl(aSocket, F_SETFL, O_NONBLOCK);
        fcntl(bSocket, F_SETFL, O_NONBLOCK);
        shareInfo->init = true;
    }

    if (SocketEnableSync == false)
        ulock.unlock();

    while (SocketServerRun)
    {
        if (SocketEnableSync == true)
            ulock.unlock();

        FD_ZERO(&readfds);
        FD_ZERO(&exceptfds);
        FD_SET(aSocket, &readfds);
        FD_SET(aSocket, &exceptfds);

        struct timeval timeoutUse = {
            static_cast<time_t>(PollingIntervalMs / 1000),
            static_cast<suseconds_t>((PollingIntervalMs % 1000) * 1000)};

        int result = select(aSocket + 1, &readfds, nullptr, &exceptfds, &timeoutUse);

        if (SocketEnableSync == true)
            ulock.lock();

        if (shareInfo->close == true)
        {
            logOutputInfoConsole(headText + "Connection closed");
            break;
        }

        if (result < 0)
        {
            if (errno == EINTR)
                continue;
            logOutputErrorConsole(headText + "select error on aSocket: " + std::string(strerror(errno)));
            break;
        }
        if (result == 0)
        {
            if (SocketEnableSync == false)
                ulock.lock();
            shareInfo->timeout += PollTimeSeconds / 2;
            if (SocketEnableSync == false)
                ulock.unlock();
            if (ConnectTimeout > 0 && shareInfo->timeout > ConnectTimeout)
            {
                logOutputWarnConsole(headText + "Connect timeout " + std::to_string(shareInfo->timeout));
                break;
            }
            else
                continue;
        }
        if (SocketEnableSync == false)
            ulock.lock();
        shareInfo->timeout = 0;
        if (SocketEnableSync == false)
            ulock.unlock();

        if (FD_ISSET(aSocket, &exceptfds))
        {
            logOutputErrorConsole(headText + "Exception detected on aSocket");
            break;
        }

        ssize_t recvNum = 0;
        recvNum = recv(aSocket, buffer, bufferSize, 0);
        if (recvNum < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            logOutputErrorConsole(headText + "recv error on aSocket: " + std::string(strerror(errno)));
            break;
        }
        if (recvNum == 0)
        {
            logOutputInfoConsole(headText + "aSocket closed by peer (recv=0)");
            break;
        }

        logOutputDebugConsole(headText + "Received " + std::to_string(recvNum) + " bytes from aSocket");

        if (SocketEnableSync == true)
            ulock.unlock();

        FD_ZERO(&writefds);
        FD_SET(bSocket, &writefds);
        FD_SET(bSocket, &exceptfds);
        timeoutUse = {
            static_cast<time_t>(PollingIntervalMs / 1000),
            static_cast<suseconds_t>((PollingIntervalMs % 1000) * 1000)};

        result = select(bSocket + 1, nullptr, &writefds, &exceptfds, &timeoutUse);

        if (SocketEnableSync == true)
            ulock.lock();

        if (shareInfo->close == true)
        {
            logOutputInfoConsole(headText + "Connection closed");
            break;
        }
        if (result <= 0)
        {
            logOutputErrorConsole(headText + (result < 0 ? "select error before send: " + std::string(strerror(errno)) : "Send timeout waiting for bSocket writable"));
            break;
        }
        if (FD_ISSET(bSocket, &exceptfds))
        {
            logOutputErrorConsole(headText + "Exception on bSocket before send");
            break;
        }

        size_t sendTotal = 0;
        bool isBreak = false;

        while (sendTotal < recvNum && SocketServerRun)
        {
            int sendNum = send(bSocket, buffer + sendTotal, recvNum - sendTotal, MSG_NOSIGNAL); // 修复：发送到 bSocket
            if (sendNum < 0)
            {
                logOutputErrorConsole(headText + "send error on bSocket: " + std::string(strerror(errno))); // 修复：日志更明确
                isBreak = true;
                break;
            }
            sendTotal += sendNum;
        }
        if (isBreak)
            break;
        if (SocketEnableSync == false)
            ulock.lock();
        shareInfo->timeout = 0;
        if (SocketEnableSync == false)
            ulock.unlock();
        logOutputDebugConsole(headText + "Sent " + std::to_string(sendTotal) + " bytes to bSocket");
    }

    if (SocketEnableSync == true)
        ulock.unlock();

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
    if (!isIpAllowed(tlsClientInfo->ip_str))
    {
        logOutputWarnConsole("Access denied: IP '" + std::string(tlsClientInfo->ip_str) + "' is in the BAN list.");
        if (tlsClientInfo->ssl)
        {
            SSL_set_shutdown(tlsClientInfo->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
            SSL_shutdown(tlsClientInfo->ssl);
            SSL_free(tlsClientInfo->ssl);
        }
        if (tlsClientInfo->fd >= 0)
        {
            close(tlsClientInfo->fd);
        }
    }

    // 必须复制TlsClientInfo
    TlsClientInfo *aConnectInfo = new TlsClientInfo(*tlsClientInfo);
    TlsClientInfo *bConnectInfo = new TlsClientInfo;

    const char *sni = SSL_get_servername(aConnectInfo->ssl, TLSEXT_NAMETYPE_host_name);

    if (connectTlsServer(bConnectInfo, sni) < 0)
    {
        logOutputErrorConsole("Failed to connect to tls server");
        if (aConnectInfo->ssl)
        {
            SSL_set_shutdown(aConnectInfo->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
            SSL_shutdown(aConnectInfo->ssl);
            SSL_free(aConnectInfo->ssl);
        }
        if (aConnectInfo->fd >= 0)
        {
            close(aConnectInfo->fd);
        }

        if (bConnectInfo->ssl)
        {
            SSL_set_shutdown(bConnectInfo->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
            SSL_shutdown(bConnectInfo->ssl);
            SSL_free(bConnectInfo->ssl);
            bConnectInfo->ssl = NULL; // 避免重复释放
        }
        if (bConnectInfo->fd >= 0)
        {
            close(bConnectInfo->fd);
            bConnectInfo->fd = -1; // 标记为已关闭
        }
        
        // 删除重复的shutdown和close调用
        // shutdown(aConnectInfo->fd, SHUT_RDWR);  // 已在上面处理
        // shutdown(bConnectInfo->fd, SHUT_RDWR);  // 已在上面处理
        // close(aConnectInfo->fd);  // 已在上面处理  
        // close(bConnectInfo->fd);  // 已在上面处理
        
        delete aConnectInfo;
        delete bConnectInfo;
        return;
    }

    logOutputInfoConsole("New tls connection from " + std::string(tlsClientInfo->ip_str) + ":" + std::to_string(tlsClientInfo->port));

    threadPool.pushMission(tlsProxyWorker, aConnectInfo, bConnectInfo);
}

void tlsListenerCallback()
{
    listenTlsServer(tlsServerCallback);
}

void tlsProxyWorker(TlsClientInfo *aConnectInfo, TlsClientInfo *bConnectInfo)
{
    SSL *aSsl = aConnectInfo->ssl;
    SSL *bSsl = bConnectInfo->ssl;
    int aSocket = aConnectInfo->fd;
    int bSocket = bConnectInfo->fd;
    
    // 初始化为-1表示未创建
    int epollFd = -1;

    char *bufferAtoB = new char[clientSocketBufferSize];
    char *bufferBtoA = new char[serverSocketBufferSize];

    // 用于标记是否需要执行清理逻辑的 lambda
    auto cleanup = [&]() {
        if (epollFd != -1)
        {
            close(epollFd);
        }
        
        delete[] bufferAtoB;
        delete[] bufferBtoA;
        
        if (bSsl)
        {
            SSL_set_shutdown(bSsl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
            SSL_shutdown(bSsl);
            SSL_free(bSsl);
        }
        if (bSocket >= 0)
        {
            close(bSocket);
        }
        delete bConnectInfo;

        if (aSsl)
        {
            SSL_set_shutdown(aSsl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
            SSL_shutdown(aSsl);
            SSL_free(aSsl);
        }
        if (aSocket >= 0)
        {
            close(aSocket);
        }
        delete aConnectInfo;
        
        logOutputInfoConsole("TLS proxy worker stopped");
    };

    if (TlsNoBlock)
    {
        fcntl(aSocket, F_SETFL, O_NONBLOCK);
        fcntl(bSocket, F_SETFL, O_NONBLOCK);
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

    const float PollTimeSeconds = (float)PollingIntervalMs / 1000.0f;
    float timeout = 0;

    while (TlsServerRun)
    {
        int eventsNumber = epoll_wait(epollFd, events, 2, PollingIntervalMs);
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
            if (ConnectTimeout > 0 && timeout > ConnectTimeout)
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
            if (eventFlags & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
            {
                logOutputErrorConsole("tls Proxy: EPOLLHUP | EPOLLRDHUP | EPOLLERR on fd " + std::to_string(activeFd));
                isBreak = true;
                break;
            }
            if (eventFlags & EPOLLIN)
            {
                SSL *srcSsl = activeFd == aSocket ? aSsl : bSsl;
                SSL *dstSsl = activeFd == aSocket ? bSsl : aSsl;
                bool isAtoB = activeFd == aSocket;
                char *buffer = isAtoB ? bufferAtoB : bufferBtoA;
                int bufferSize = isAtoB ? clientSocketBufferSize : serverSocketBufferSize;

                int sslReadNum = SSL_read(srcSsl, buffer, bufferSize);
                if (TlsNoBlock == false)
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
                    while (TlsServerRun && sentTotal < sslReadNum)
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
                                FD_SET(bSocket, &writefds);

                                struct timeval timeoutUse = {
                                    static_cast<time_t>(PollingIntervalMs / 1000),
                                    static_cast<suseconds_t>((PollingIntervalMs % 1000) * 1000)};

                                int ret = select(bSocket + 1, NULL, &writefds, NULL, &timeoutUse);
                                if (ret <= 0)
                                {
                                    logOutputErrorConsole("tls Proxy: bSsl write select failed: " + std::string(strerror(errno)));
                                    isBreak = true;
                                    break;
                                }
                                timeout += PollTimeSeconds;
                                if (timeout > ConnectTimeout)
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
                    if (recvErrno == SSL_ERROR_ZERO_RETURN)
                        logOutputInfoConsole("tls Proxy: aSsl closed connection");
                    else
                        logOutputErrorConsole("tls Proxy: aSsl read failed code: " + std::to_string(recvErrno));
                    isBreak = true;
                    break;
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
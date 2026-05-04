#include "nTls.h" // 根据实际情况包含头文件

static TlsClientCallback tls_callback;
static int tls_initialized = 0;        // OpenSSL 库初始化标志
static int client_ctx_init_failed = 0; // 避免重复尝试失败的客户端 CTX

// 前向声明
static int verify_cert_hostname(X509 *cert, const char *expected_host);
static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg);
static void socket_server_callback(int fd, SocketClientInfo *info);

// ===================== 证书主机名验证（RFC 6125） =====================
static int verify_cert_hostname(X509 *cert, const char *expected_host)
{
    if (!cert || !expected_host || *expected_host == '\0')
        return 0;

    // 1. 检查 Subject Alternative Name (SAN) 扩展
    GENERAL_NAMES *names = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    int matched = 0;
    if (names)
    {
        int num = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < num && !matched; i++)
        {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS)
            {
                ASN1_IA5STRING *asn1_str = name->d.dNSName;
                if (asn1_str && asn1_str->data && asn1_str->length > 0)
                {
                    const char *dns_name = (const char *)asn1_str->data;
                    size_t name_len = asn1_str->length;
                    // 检查嵌入的空字符（安全）
                    if (memchr(dns_name, '\0', name_len) != NULL)
                        continue;

                    // 精确匹配
                    if (strlen(expected_host) == name_len &&
                        strncasecmp(expected_host, dns_name, name_len) == 0)
                    {
                        matched = 1;
                        break;
                    }
                    // 通配符匹配：* 必须出现在最左标签，且仅匹配一个标签
                    if (name_len > 2 && dns_name[0] == '*' && dns_name[1] == '.')
                    {
                        const char *host_dot = strchr(expected_host, '.');
                        if (host_dot && strcasecmp(host_dot + 1, dns_name + 2) == 0)
                        {
                            matched = 1;
                            break;
                        }
                    }
                }
            }
        }
        GENERAL_NAMES_free(names);
        if (matched)
            return 1;
    }

    // 2. 回退到 Common Name (CN) —— 仅当 SAN 不存在时
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name)
    {
        char cn_buffer[256];
        int cn_length = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn_buffer, sizeof(cn_buffer));
        if (cn_length > 0 && cn_length < (int)sizeof(cn_buffer))
        {
            cn_buffer[cn_length] = '\0';
            size_t cn_str_len = strlen(cn_buffer);
            // 精确匹配
            if (strcasecmp(expected_host, cn_buffer) == 0)
                return 1;
            // 通配符 CN（兼容旧证书）
            if (cn_str_len > 2 && cn_buffer[0] == '*' && cn_buffer[1] == '.')
            {
                const char *host_dot = strchr(expected_host, '.');
                if (host_dot && strcasecmp(host_dot + 1, cn_buffer + 2) == 0)
                    return 1;
            }
        }
    }
    return 0;
}

// ===================== ALPN 服务端回调 =====================
static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg)
{
    // 支持的协议（长度前缀格式），优先级 h2 > http/1.1
    static const unsigned char supported_protocols[] = {
        0x02, 'h', '2',
        0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const unsigned char *p = in;
    while (p < in + inlen)
    {
        unsigned char len = *p++;
        if (p + len > in + inlen)
            break; // 畸形包
        // 在 supported_protocols 中查找
        const unsigned char *q = supported_protocols;
        while (q < supported_protocols + sizeof(supported_protocols))
        {
            unsigned char qlen = *q++;
            if (q + qlen > supported_protocols + sizeof(supported_protocols))
                break;
            if (len == qlen && memcmp(p, q, len) == 0)
            {
                *out = q; // 指向支持的协议字符串
                *outlen = qlen;
                char buf[20];
                snprintf(buf, sizeof(buf), "%.*s", qlen, q);
                logOutputInfoConsoleCharString("ALPN: Negotiated ");
                logOutputInfoConsoleCharString(buf);
                return SSL_TLSEXT_ERR_OK;
            }
            q += qlen;
        }
        p += len;
    }
    logOutputWarnConsoleCharString("ALPN: Client does not support any of our protocols (h2, http/1.1)");
    return SSL_TLSEXT_ERR_NOACK;
}

// ===================== 服务端回调：处理新 TCP 连接并升级为 TLS =====================
static void socket_server_callback(int fd, SocketClientInfo *info)
{
    if (!serverTlsCtx)
    {
        logOutputErrorConsoleCharString("socket_server_callback: serverTlsCtx is not initialized");
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    SSL *ssl = NULL;
    int flagsBackup = 0;

    if (TlsNoBlockConnect)
    {
        flagsBackup = fcntl(fd, F_GETFL, 0);
        if (flagsBackup == -1)
        {
            logOutputErrorConsoleCharString("Get tls socket block flags error");
            return;
        }
        int flags = flagsBackup | O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1)
        {
            logOutputErrorConsoleCharString("Set tls socket no block flags error");
            return;
        }
    }

    do
    {
        ssl = SSL_new(serverTlsCtx);
        if (!ssl)
        {
            logOutputErrorConsoleCharString("socket_server_callback: SSL_new failed");
            break;
        }
        if (!SSL_set_fd(ssl, fd))
        {
            logOutputErrorConsoleCharString("socket_server_callback: SSL_set_fd failed");
            break;
        }

        int sslAccept = 0;
        int sslConnErr = 0;
        while (1)
        {
            sslAccept = SSL_accept(ssl);
            if (sslAccept == 1)
            {
                sslConnErr = 0;
                break;
            }
            sslConnErr = SSL_get_error(ssl, sslAccept);
            if (sslConnErr == SSL_ERROR_WANT_READ || sslConnErr == SSL_ERROR_WANT_WRITE)
            {
                if (TlsNoBlockConnect)
                {
                    fd_set readfds, writefds;
                    FD_ZERO(&readfds);
                    FD_ZERO(&writefds);
                    if (sslConnErr == SSL_ERROR_WANT_READ)
                        FD_SET(fd, &readfds);
                    else
                        FD_SET(fd, &writefds);

                    struct timeval timeout;
                    timeout.tv_sec = PollingIntervalMs / 1000;
                    timeout.tv_usec = (PollingIntervalMs % 1000) * 1000;
                    int selectRet = select(fd + 1, &readfds, &writefds, NULL, &timeout);
                    if (selectRet < 0)
                    {
                        logOutputErrorConsoleCharString("select error during SSL handshake");
                        break;
                    }
                    else if (selectRet == 0)
                    {
                        logOutputWarnConsoleCharString("SSL handshake timeout");
                        break;
                    }
                    // 继续循环，重新调用 SSL_accept
                    continue;
                }
                else
                {
                    // 阻塞模式下不应该出现，但继续重试
                    continue;
                }
            }
            else
            {
                // 其他错误，退出循环
                break;
            }
        }

        if (sslConnErr != SSL_ERROR_NONE)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char error_string[512];
            snprintf(error_string, sizeof(error_string), "SSL accept failed for client %s:%d - %s",
                     info->ip_str, info->port, err_buf);
            logOutputErrorConsoleCharString(error_string);
            break;
        }

        logOutputInfoConsoleCharString("TLS handshake completed successfully.");

        if (TlsNoBlockConnect)
        {
            // 恢复原始阻塞标志
            if (fcntl(fd, F_SETFL, flagsBackup) == -1)
            {
                logOutputErrorConsoleCharString("Restore socket flags error");
                break;
            }
        }

        // 填充 TlsClientInfo
        TlsClientInfo client_info = {0};
        client_info.fd = fd;
        client_info.ssl_ctx = serverTlsCtx;
        client_info.ssl = ssl;
        memcpy(&client_info.addr, &info->addr, info->addr_len);
        client_info.addr_len = info->addr_len;
        strncpy(client_info.ip_str, info->ip_str, INET_ADDRSTRLEN);
        client_info.ip_str[INET_ADDRSTRLEN - 1] = '\0';
        client_info.port = info->port;

        if (tls_callback)
        {
            tls_callback(fd, &client_info);
        }
        else
        {
            logOutputErrorConsoleCharString("socket_server_callback: tls_callback is null");
            if (ssl)
            {
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (fd >= 0)
                close(fd);
        }
        return; // 成功，SSL 对象所有权已转移给回调方

    } while (0);

    // 错误清理
    if (ssl)
    {
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
}

// ===================== TLS 服务器初始化 =====================
void initTlsServer()
{
    logOutputInfoConsoleCharString("Initializing TLS Server...");

    // 现代 OpenSSL 初始化（替换废弃 API）
    if (!tls_initialized)
    {
        OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_LOAD_CONFIG, NULL);
        tls_initialized = 1;
        tlsInit = true; // 保持原有全局标志
    }

    const SSL_METHOD *method = TLS_server_method();
    serverTlsCtx = SSL_CTX_new(method);
    if (!serverTlsCtx)
    {
        logOutputErrorConsoleCharString("Failed to create server SSL_CTX");
        return;
    }

    // 设置协议版本范围（TLS 1.2 最低，1.3 最高）
    if (!SSL_CTX_set_min_proto_version(serverTlsCtx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(serverTlsCtx, TLS1_3_VERSION))
    {
        logOutputErrorConsoleCharString("Failed to set TLS version range");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_chain_file(serverTlsCtx, tlsCertFileChar) <= 0)
    {
        char error_msg[512];
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        snprintf(error_msg, sizeof(error_msg), "Failed to load server certificate chain file '%s': %s",
                 tlsCertFileChar, err_buf);
        logOutputErrorConsoleCharString(error_msg);
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(serverTlsCtx, tlsKeyFileChar, SSL_FILETYPE_PEM) <= 0)
    {
        char error_msg[512];
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        snprintf(error_msg, sizeof(error_msg), "Failed to load server private key file '%s': %s",
                 tlsKeyFileChar, err_buf);
        logOutputErrorConsoleCharString(error_msg);
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }
    if (!SSL_CTX_check_private_key(serverTlsCtx))
    {
        logOutputErrorConsoleCharString("Server private key does not match the certificate public key");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    // 设置 ALPN 回调
    SSL_CTX_set_alpn_select_cb(serverTlsCtx, alpn_select_callback, NULL);

    // 设置 TLS 1.3 密码套件
    if (!SSL_CTX_set_ciphersuites(serverTlsCtx,
                                  "TLS_AES_256_GCM_SHA384:"
                                  "TLS_CHACHA20_POLY1305_SHA256:"
                                  "TLS_AES_128_GCM_SHA256"))
    {
        logOutputErrorConsoleCharString("Failed to set server TLS 1.3 ciphersuites");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }
    // 同时设置 TLS 1.2 及以下密码套件
    if (!SSL_CTX_set_cipher_list(serverTlsCtx,
                                 "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                 "ECDHE-RSA-AES256-GCM-SHA384:"
                                 "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                 "ECDHE-RSA-CHACHA20-POLY1305:"
                                 "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                 "ECDHE-RSA-AES128-GCM-SHA256"))
    {
        logOutputErrorConsoleCharString("Failed to set server TLS 1.2 cipher list");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    // 安全选项
    SSL_CTX_set_options(serverTlsCtx,
                        SSL_OP_NO_TICKET |
                            SSL_OP_NO_RENEGOTIATION |
                            SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(serverTlsCtx, SSL_SESS_CACHE_OFF);

    logOutputInfoConsoleCharString("TLS Server context initialized successfully.");

    // 初始化底层 TCP 服务器
    initSocketServer();
    if (socketServerFd < 0)
    {
        logOutputErrorConsoleCharString("Failed to initialize underlying TCP socket server");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }
    logOutputInfoConsoleCharString("TLS Server initialization complete.");
}

// ===================== 开始监听 =====================
void listenTlsServer(TlsClientCallback callback)
{
    if (!callback)
    {
        logOutputErrorConsoleCharString("listenTlsServer: callback is null");
        return;
    }
    tls_callback = callback;
    TlsServerRun = true;
    logOutputInfoConsoleCharString("Starting to listen for TLS connections...");
    listenSocketServer(socket_server_callback);
}

// ===================== 关闭服务器 =====================
void closeTlsServer()
{
    logOutputInfoConsoleCharString("Shutting down TLS Server...");
    TlsServerRun = false;
    closeSocketServer();
    logOutputInfoConsoleCharString("TLS Server shut down.");
}

// ===================== TLS 客户端连接 =====================
int connectTlsServer(TlsClientInfo *client_info, const char *sni)
{
    if (!client_info)
    {
        logOutputErrorConsoleCharString("connectTlsServer: Invalid client_info pointer");
        return -1;
    }
    memset(client_info, 0, sizeof(TlsClientInfo));

    SocketClientInfo socketInfo = {0};
    if (connectSocketServer(&socketInfo) < 0 || socketInfo.fd < 0)
    {
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer failed");
        return -1;
    }

    SSL_CTX *temp_ctx = NULL;
    SSL *ssl = NULL;
    int ret = -1;

    do
    {
        // ---------- 创建或复用客户端 SSL_CTX ----------
        if (!clientTlsCtx && !client_ctx_init_failed)
        {
            logOutputInfoConsoleCharString("Initializing client SSL_CTX...");
            const SSL_METHOD *method = TLS_client_method();
            temp_ctx = SSL_CTX_new(method);
            if (!temp_ctx)
            {
                logOutputErrorConsoleCharString("connectTlsServer: SSL_CTX_new failed");
                client_ctx_init_failed = 1;
                break;
            }

            // 设置协议版本范围
            if (!SSL_CTX_set_min_proto_version(temp_ctx, TLS1_2_VERSION) ||
                !SSL_CTX_set_max_proto_version(temp_ctx, TLS1_3_VERSION))
            {
                logOutputErrorConsoleCharString("connectTlsServer: Failed to set TLS version range");
                SSL_CTX_free(temp_ctx);
                client_ctx_init_failed = 1;
                break;
            }

            // 加载 CA 证书（用于验证服务端）
            if (tlsServerCaFileChar && strlen(tlsServerCaFileChar) > 0)
            {
                logOutputInfoConsoleCharString("Loading custom CA file: ");
                logOutputInfoConsoleCharString(tlsServerCaFileChar);
                if (SSL_CTX_load_verify_locations(temp_ctx, tlsServerCaFileChar, NULL) != 1)
                {
                    logOutputErrorConsoleCharString("Failed to load CA file");
                    SSL_CTX_free(temp_ctx);
                    client_ctx_init_failed = 1;
                    break;
                }
                logOutputInfoConsoleCharString("Custom CA file loaded.");
            }
            else
            {
                logOutputInfoConsoleCharString("Using system default CA paths.");
                if (SSL_CTX_set_default_verify_paths(temp_ctx) != 1)
                {
                    logOutputWarnConsoleCharString("Warning: Could not load system CA paths");
                    // 不致命，继续
                }
            }

            SSL_CTX_set_verify(temp_ctx, SSL_VERIFY_PEER, NULL);

            // 设置 TLS 1.3 密码套件
            if (!SSL_CTX_set_ciphersuites(temp_ctx,
                                          "TLS_AES_256_GCM_SHA384:"
                                          "TLS_CHACHA20_POLY1305_SHA256:"
                                          "TLS_AES_128_GCM_SHA256"))
            {
                logOutputErrorConsoleCharString("Failed to set client TLS 1.3 ciphersuites");
                SSL_CTX_free(temp_ctx);
                client_ctx_init_failed = 1;
                break;
            }
            // 设置 TLS 1.2 密码套件
            if (!SSL_CTX_set_cipher_list(temp_ctx,
                                         "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                         "ECDHE-RSA-AES256-GCM-SHA384:"
                                         "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                         "ECDHE-RSA-CHACHA20-POLY1305:"
                                         "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                         "ECDHE-RSA-AES128-GCM-SHA256"))
            {
                logOutputErrorConsoleCharString("Failed to set client TLS 1.2 cipher list");
                SSL_CTX_free(temp_ctx);
                client_ctx_init_failed = 1;
                break;
            }

            SSL_CTX_set_options(temp_ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);

            clientTlsCtx = temp_ctx;
            temp_ctx = NULL;
            logOutputInfoConsoleCharString("Client SSL_CTX created and stored.");
        }

        if (!clientTlsCtx)
        {
            logOutputErrorConsoleCharString("No available client SSL_CTX");
            break;
        }

        // ---------- 创建 SSL 对象 ----------
        ssl = SSL_new(clientTlsCtx);
        if (!ssl)
        {
            logOutputErrorConsoleCharString("SSL_new failed");
            break;
        }

        // 设置 ALPN 协议（h2 优先）
        static const unsigned char alpn_protos[] = {
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_set_alpn_protos(ssl, alpn_protos, sizeof(alpn_protos)) != 0)
        {
            logOutputErrorConsoleCharString("SSL_set_alpn_protos failed");
            break;
        }

        // ---------- 确定主机名 ----------
        const char *verify_host = NULL;
        if (tlsClientHostNameChar && tlsClientHostNameChar[0] != '\0')
            verify_host = tlsClientHostNameChar;
        else if (sni && sni[0] != '\0')
            verify_host = sni;
        else
        {
            logOutputErrorConsoleCharString("No hostname for certificate verification");
            break;
        }

        // 设置 SNI
        const char *used_sni = NULL;
        if (tlsClientSniChar && tlsClientSniChar[0] != '\0')
            used_sni = tlsClientSniChar;
        else if (sni && sni[0] != '\0')
            used_sni = sni;
        if (used_sni && !SSL_set_tlsext_host_name(ssl, used_sni))
        {
            logOutputErrorConsoleCharString("Failed to set SNI extension");
            // 不中断，继续
        }

        SSL_set_fd(ssl, socketInfo.fd);

        // ---------- TLS 握手 ----------
        int sslConnect = SSL_connect(ssl);
        if (sslConnect != 1)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char output_buf[512];
            snprintf(output_buf, sizeof(output_buf), "SSL_connect to %s:%d failed: %s",
                     clientHostChar, clientPort, err_buf);
            logOutputErrorConsoleCharString(output_buf);
            break;
        }

        // ---------- 验证服务端证书 ----------
        X509 *server_cert = SSL_get_peer_certificate(ssl);
        if (!server_cert)
        {
            logOutputErrorConsoleCharString("Server did not present a certificate");
            break;
        }
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK)
        {
            logOutputErrorConsoleCharString("Certificate verification failed:");
            logOutputErrorConsoleCharString(X509_verify_cert_error_string(verify_result));
            X509_free(server_cert);
            break;
        }
        if (!verify_cert_hostname(server_cert, verify_host))
        {
            logOutputErrorConsoleCharString("Hostname verification failed, expected: ");
            logOutputErrorConsoleCharString(verify_host);
            X509_free(server_cert);
            break;
        }
        X509_free(server_cert);

        logOutputInfoConsoleCharString("TLS handshake with remote server completed successfully.");

        // 记录协商的 ALPN 协议
        const unsigned char *negotiated_proto = NULL;
        unsigned int proto_len = 0;
        SSL_get0_alpn_selected(ssl, &negotiated_proto, &proto_len);
        if (negotiated_proto && proto_len > 0)
        {
            char buf[20];
            snprintf(buf, sizeof(buf), "%.*s", proto_len, negotiated_proto);
            logOutputInfoConsoleCharString("ALPN negotiated: ");
            logOutputInfoConsoleCharString(buf);
        }
        else
        {
            logOutputInfoConsoleCharString("ALPN: No protocol negotiated.");
        }

        // 填充输出结构
        client_info->fd = socketInfo.fd;
        client_info->ssl = ssl;
        client_info->ssl_ctx = clientTlsCtx;
        memcpy(&client_info->addr, &socketInfo.addr, socketInfo.addr_len);
        client_info->addr_len = socketInfo.addr_len;
        strncpy(client_info->ip_str, socketInfo.ip_str, INET_ADDRSTRLEN);
        client_info->ip_str[INET_ADDRSTRLEN - 1] = '\0';
        client_info->port = socketInfo.port;

        ret = 0; // 成功

    } while (0);

    if (ret != 0)
    {
        // 错误清理
        if (ssl)
            SSL_free(ssl);
        if (temp_ctx) // 如果临时 CTX 未被保存到全局，释放它
            SSL_CTX_free(temp_ctx);
        if (socketInfo.fd >= 0)
        {
            shutdown(socketInfo.fd, SHUT_RDWR);
            close(socketInfo.fd);
        }
        return -1;
    }
    return 0;
}

// ===================== 清理所有资源 =====================
void closeTlsResource()
{
    logOutputInfoConsoleCharString("Cleaning up all TLS resources...");
    if (serverTlsCtx)
    {
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
    }
    if (clientTlsCtx)
    {
        SSL_CTX_free(clientTlsCtx);
        clientTlsCtx = NULL;
    }
    OPENSSL_cleanup();
    tlsInit = false;
    tls_initialized = 0;
    client_ctx_init_failed = 0;
    logOutputInfoConsoleCharString("All TLS resources cleaned up.");
}
#include "nTls.h" // 根据实际情况包含头文件

static TlsClientCallback tls_callback;

/**
 * @brief 验证证书中的主机名是否匹配预期主机名。
 * @param cert 证书指针。
 * @param expected_host 期望的主机名。
 * @return 1 如果匹配，0 如果不匹配。
 */
static int verify_cert_hostname(X509 *cert, const char *expected_host)
{
    if (!cert || !expected_host)
    {
        return 0;
    }

    // 检查 Subject Alternative Name (SAN)
    GENERAL_NAMES *names = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names)
    {
        int num_names = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < num_names; i++)
        {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS)
            {
                ASN1_IA5STRING *asn1_str = name->d.dNSName;
                if (asn1_str && asn1_str->data && asn1_str->length > 0)
                {
                    const char *dns_name = (const char *)asn1_str->data;
                    if (strlen(dns_name) == (size_t)asn1_str->length)
                    { // Check for embedded nulls
                        if (strcasecmp(expected_host, dns_name) == 0)
                        {
                            GENERAL_NAMES_free(names);
                            return 1;
                        }
                        // Handle wildcard matching if needed: e.g., *.example.com matches sub.example.com
                        if (dns_name[0] == '*' && strlen(expected_host) >= strlen(dns_name) &&
                            strcasecmp(expected_host + strlen(expected_host) - strlen(dns_name) + 1, dns_name + 1) == 0)
                        {
                            GENERAL_NAMES_free(names);
                            return 1;
                        }
                    }
                }
            }
        }
        GENERAL_NAMES_free(names);
    }

    // Fallback to Common Name (CN)
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name)
    {
        char cn_buffer[256];
        int cn_length = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn_buffer, sizeof(cn_buffer));
        if (cn_length > 0)
        {
            if (strcmp(expected_host, cn_buffer) == 0)
            {
                return 1;
            }
            // Handle wildcard CN if needed
            if (cn_buffer[0] == '*' && strlen(expected_host) >= strlen(cn_buffer) &&
                strcasecmp(expected_host + strlen(expected_host) - strlen(cn_buffer) + 1, cn_buffer + 1) == 0)
            {
                return 1;
            }
        }
    }

    return 0; // No match found
}

// --- ALPN 回调函数 ---

/**
 * @brief ALPN 回调函数，用于协商应用层协议。
 * @param ssl SSL 对象指针。
 * @param out 选中的协议。
 * @param outlen 选中的协议长度。
 * @param in 客户端提供的协议列表。
 * @param inlen 客户端提供的协议列表长度。
 * @param arg 用户自定义参数。
 * @return SSL_TLSEXT_ERR_OK 表示成功。
 */
static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg)
{
    // 我们的首选协议列表 (优先级 h2 > http/1.1)
    static const unsigned char supported_protocols[] = {
        0x02, 'h', '2',                              // Length-prefixed "h2"
        0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' // Length-prefixed "http/1.1"
    };
    const unsigned int supported_len = sizeof(supported_protocols);

    const unsigned char *client_pos = in;
    const unsigned char *client_end = in + inlen;

    // 遍历客户端提供的协议列表
    while (client_pos < client_end)
    {
        unsigned char client_len = *client_pos++;
        if (client_pos + client_len > client_end)
        {
            // Malformed input, skip or reject
            logOutputWarnConsoleCharString("ALPN: Malformed client protocol list.");
            break;
        }

        // 在我们的支持列表中查找匹配项
        const unsigned char *our_pos = supported_protocols;
        const unsigned char *our_end = supported_protocols + supported_len;
        while (our_pos < our_end)
        {
            unsigned char our_len = *our_pos++;
            if (our_pos + our_len > our_end)
                break; // Should not happen

            if (client_len == our_len && memcmp(client_pos, our_pos, our_len) == 0)
            {
                *out = our_pos; // Point to the protocol string inside our supported list
                *outlen = our_len;
                char negotiated_protocol[20];
                snprintf(negotiated_protocol, sizeof(negotiated_protocol), "%.*s", our_len, (char *)*out);
                logOutputInfoConsoleCharString("ALPN: Negotiated ");
                logOutputInfoConsoleCharString(negotiated_protocol);
                return SSL_TLSEXT_ERR_OK;
            }
            our_pos += our_len;
        }
        client_pos += client_len;
    }

    // 如果客户端不支持任何我们列出的协议，拒绝协商
    logOutputWarnConsoleCharString("ALPN: Client does not support any of our protocols (h2, http/1.1), rejecting.");
    return SSL_TLSEXT_ERR_NOACK;
}

// --- 内部回调函数 ---

/**
 * @brief 内部回调函数，用于处理新建立的原始TCP连接并升级为TLS。
 * @param fd 新的TCP套接字描述符。
 * @param info 包含客户端地址等信息的结构体。
 */
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

        // --- 服务端：不再设置客户端证书验证 ---
        // SSL_CTX_set_verify(serverTlsCtx, SSL_VERIFY_NONE, NULL); // 默认即为不验证客户端
        // SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

        int sslAccept = SSL_accept(ssl);
        if (sslAccept <= 0)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char error_string[512];
            snprintf(error_string, sizeof(error_string), "SSL accept error: %s", err_buf);
            logOutputErrorConsoleCharString(error_string);
            break; // 跳出do-while，准备清理
        }

        logOutputInfoConsoleCharString("TLS handshake completed successfully.");

        // 填充 TlsClientInfo 结构体
        TlsClientInfo client_info = {0}; // Initialize to zero
        client_info.fd = fd;
        client_info.ssl_ctx = serverTlsCtx; // 服务端上下文
        client_info.ssl = ssl;

        // 复制地址信息
        if (info->addr_len <= sizeof(client_info.addr))
        {
            memcpy(&client_info.addr, &info->addr, info->addr_len);
            client_info.addr_len = info->addr_len;
        }
        else
        {
            logOutputErrorConsoleCharString("socket_server_callback: Address structure size mismatch");
            break; // 地址信息有问题，放弃处理
        }

        // 复制IP和端口
        strncpy(client_info.ip_str, info->ip_str, sizeof(client_info.ip_str) - 1);
        client_info.ip_str[sizeof(client_info.ip_str) - 1] = '\0'; // 确保结尾
        client_info.port = info->port;

        // 调用用户提供的TLS连接处理回调
        // 注意：此处假设有一个全局的 tls_callback 变量
        extern TlsClientCallback tls_callback; // Assume declared globally
        if (tls_callback)
        {
            tls_callback(fd, &client_info);
        }
        else
        {
            logOutputErrorConsoleCharString("socket_server_callback: tls_callback is null");
            // Consider closing the connection here if no handler is set
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(fd);
        }
        return; // 成功处理，直接返回 (注意：SSL对象所有权已转移)

    } while (false); // do-while(false) 用于方便地使用break来统一清理错误情况

    // 清理错误状态下的资源
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

// --- 初始化函数 ---

/**
 * @brief 初始化TLS服务器上下文和底层TCP服务器。
 */
void initTlsServer()
{
    logOutputInfoConsoleCharString("Initializing TLS Server...");

    if (!tlsInit)
    {
        logOutputInfoConsoleCharString("Initializing OpenSSL library...");
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        tlsInit = true;
    }

    const SSL_METHOD *method = TLS_server_method();
    serverTlsCtx = SSL_CTX_new(method);
    if (!serverTlsCtx)
    {
        logOutputErrorConsoleCharString("Failed to create server SSL_CTX");
        return;
    }

    // 设置最低协议版本
    if (!SSL_CTX_set_min_proto_version(serverTlsCtx, TLS1_2_VERSION))
    {
        logOutputErrorConsoleCharString("Failed to set minimum TLS version to 1.2");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_chain_file(serverTlsCtx, tlsCertFileChar) <= 0)
    {
        logOutputErrorConsoleCharString("Failed to load server certificate chain file");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    if (SSL_CTX_use_PrivateKey_file(serverTlsCtx, tlsKeyFileChar, SSL_FILETYPE_PEM) <= 0)
    {
        logOutputErrorConsoleCharString("Failed to load server private key file");
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

    // --- 服务端：不再加载客户端证书验证的CA ---
    // (代码块被完全移除)

    // 设置ALPN回调
    SSL_CTX_set_alpn_select_cb(serverTlsCtx, alpn_select_callback, NULL);

    // 设置密码套件
    if (!SSL_CTX_set_ciphersuites(serverTlsCtx,
                                  "TLS_AES_256_GCM_SHA384:"
                                  "TLS_CHACHA20_POLY1305_SHA256:"
                                  "TLS_AES_128_GCM_SHA256"))
    {
        logOutputErrorConsoleCharString("Failed to set server cipher suites");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    // 设置选项
    SSL_CTX_set_options(serverTlsCtx,
                        SSL_OP_NO_TICKET |
                            SSL_OP_NO_RENEGOTIATION |
                            SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_session_cache_mode(serverTlsCtx, SSL_SESS_CACHE_OFF);

    logOutputInfoConsoleCharString("TLS Server context initialized successfully.");

    // 初始化底层TCP服务器
    initSocketServer(); // Assume this function exists
    if (socketServerFd < 0)
    {
        logOutputErrorConsoleCharString("Failed to initialize underlying TCP socket server");
        SSL_CTX_free(serverTlsCtx);
        serverTlsCtx = NULL;
        return;
    }

    logOutputInfoConsoleCharString("TLS Server initialization complete.");
}

// --- 监听函数 ---

/**
 * @brief 开始监听TLS连接。
 * @param callback 当新TLS连接建立时调用的回调函数。
 */
void listenTlsServer(TlsClientCallback callback)
{
    if (!callback)
    {
        logOutputErrorConsoleCharString("listenTlsServer: callback is null");
        return;
    }
    // Store the callback globally so socket_server_callback can access it
    tls_callback = callback;
    TlsServerRun = true;
    logOutputInfoConsoleCharString("Starting to listen for TLS connections...");
    listenSocketServer(socket_server_callback); // Assume this function exists
}

// --- 关闭函数 ---

/**
 * @brief 关闭并清理TLS服务器。
 */
void closeTlsServer()
{
    logOutputInfoConsoleCharString("Shutting down TLS Server...");
    TlsServerRun = false;
    closeSocketServer(); // Assume this function exists
    logOutputInfoConsoleCharString("TLS Server shut down.");
}

// --- 客户端连接函数 ---

/**
 * @brief 连接到远程TLS服务器。
 * @param client_info 输出参数，用于存储新建立的连接信息。
 * @param sni 从原始请求中提取的SNI，用于连接目标服务器。
 * @return 0 成功，负数表示错误码。
 */
int connectTlsServer(TlsClientInfo *client_info, const char *sni)
{
    if (!client_info)
    {
        logOutputErrorConsoleCharString("connectTlsServer: Invalid client_info pointer");
        return -1;
    }
    // client_info 内容应在调用前被清零或初始化

    SocketClientInfo socketInfo = {0};
    if (connectSocketServer(&socketInfo) < 0)
    { // Assume this function exists and fills socketInfo
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer failed");
        return -1;
    }

    if (socketInfo.fd < 0)
    {
        logOutputErrorConsoleCharString("connectTlsServer: connectSocketServer returned invalid fd");
        return -1;
    }

    SSL_CTX *temp_ctx = NULL;
    SSL *ssl = NULL;

    do
    {
        /* --- SSL_CTX 初始化（客户端复用）--- */
        if (!clientTlsCtx)
        {
            logOutputInfoConsoleCharString("Initializing client SSL_CTX...");
            const SSL_METHOD *method = TLS_client_method();
            temp_ctx = SSL_CTX_new(method);
            if (!temp_ctx)
            {
                logOutputErrorConsoleCharString("connectTlsServer: SSL_CTX_new failed for client");
                break;
            }

            if (!SSL_CTX_set_min_proto_version(temp_ctx, TLS1_2_VERSION))
            {
                logOutputErrorConsoleCharString("connectTlsServer: Failed to set client minimum TLS version");
                SSL_CTX_free(temp_ctx);
                temp_ctx = NULL; // 修复：防止 double free
                break;
            }

            // --- 客户端：加载验证服务端证书的CA ---
            // 检查 tlsServerCaFileChar 是否为 NULL 或空字符串
            if (tlsServerCaFileChar && strlen(tlsServerCaFileChar) > 0)
            {
                logOutputInfoConsoleCharString("Loading custom CA file for server verification: ");
                logOutputInfoConsoleCharString(tlsServerCaFileChar);

                if (!SSL_CTX_load_verify_locations(temp_ctx, tlsServerCaFileChar, NULL))
                {
                    // 如果指定了文件但加载失败，则记录错误并退出
                    logOutputErrorConsoleCharString("connectTlsServer: Failed to load CA file for server certificate verification");
                    logOutputErrorConsoleCharString("CA File Path: ");
                    logOutputErrorConsoleCharString(tlsServerCaFileChar);
                    SSL_CTX_free(temp_ctx);
                    temp_ctx = NULL; // 修复：防止 double free
                    break;
                }
                logOutputInfoConsoleCharString("Custom CA file loaded successfully.");
            }
            else
            {
                // tlsServerCaFileChar 为 NULL 或空，使用系统默认路径
                logOutputInfoConsoleCharString("Using system default CA paths for server certificate verification.");
                if (!SSL_CTX_set_default_verify_paths(temp_ctx))
                {
                    // 理论上，设置系统默认路径很少失败，但为了健壮性可以检查
                    logOutputErrorConsoleCharString("Warning: Could not load system default CA paths. Verification may fail.");
                    // 我们可以选择继续还是失败。通常，即使此调用失败，系统路径也可能已自动加载。
                    // 为了更严格的安全，可以选择 break 并失败。
                    // 为了兼容性，我们选择继续，并依赖 SSL_CTX_set_verify 的行为。
                    // 如果你希望在此失败，则取消下面三行的注释。
                    /*
                    SSL_CTX_free(temp_ctx);
                    temp_ctx = NULL; // 修复：防止 double free
                    break;
                    */
                }
            }

            // 启用对等方（服务器）证书验证
            SSL_CTX_set_verify(temp_ctx, SSL_VERIFY_PEER, NULL);

            if (!SSL_CTX_set_ciphersuites(temp_ctx,
                                          "TLS_AES_256_GCM_SHA384:"
                                          "TLS_CHACHA20_POLY1305_SHA256:"
                                          "TLS_AES_128_GCM_SHA256"))
            {
                logOutputErrorConsoleCharString("connectTlsServer: Failed to set client cipher suites");
                SSL_CTX_free(temp_ctx);
                temp_ctx = NULL; // 修复：防止 double free
                break;
            }

            SSL_CTX_set_options(temp_ctx,
                                SSL_OP_NO_TICKET |
                                    SSL_OP_NO_RENEGOTIATION);

            // SSL_CTX_set_session_cache_mode(temp_ctx, SSL_SESS_CACHE_OFF);

            clientTlsCtx = temp_ctx; // 成功后赋值给全局变量
            temp_ctx = NULL;         // Prevent double free on error
            logOutputInfoConsoleCharString("Client SSL_CTX initialized and stored globally.");
        }
        else
        {
            logOutputDebugConsoleCharString("Reusing existing client SSL_CTX.");
        }

        /* --- 创建 SSL 对象 --- */
        ssl = SSL_new(clientTlsCtx);
        if (!ssl)
        {
            logOutputErrorConsoleCharString("connectTlsServer: SSL_new failed");
            break;
        }

        // 设置ALPN协议 (h2 优先于 http/1.1)
        const unsigned char alpn_protos[] = {
            0x02, 'h', '2',                              // Length-prefixed "h2"
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' // Length-prefixed "http/1.1"
        };
        if (SSL_set_alpn_protos(ssl, alpn_protos, sizeof(alpn_protos)) != 0)
        {
            logOutputErrorConsoleCharString("connectTlsServer: SSL_set_alpn_protos failed");
            break;
        }

        /* --- 确定用于主机名验证的目标 --- */
        const char *verify_host = NULL;
        if (tlsClientHostNameChar && tlsClientHostNameChar[0] != '\0')
        {
            verify_host = tlsClientHostNameChar;
        }
        else if (sni && sni[0] != '\0')
        {
            verify_host = sni;
        }
        else
        {
            // If no specific host is given, try to derive it from socket info (not ideal, often an IP)
            // A better approach might be to pass the original hostname to this function.
            // For now, let's assume SNI should be used for verification if available.
            if (sni && sni[0] != '\0')
            {
                verify_host = sni;
            }
            else
            {
                logOutputErrorConsoleCharString("connectTlsServer: Error: No valid hostname for certificate verification!");
                SSL_free(ssl);
                close(socketInfo.fd);
                return -8;
            }
        }

        /* --- 设置 SNI --- */
        const char *used_sni = NULL;
        if (tlsClientSniChar && tlsClientSniChar[0] != '\0')
        {
            used_sni = tlsClientSniChar;
        }
        else if (sni && sni[0] != '\0')
        {
            used_sni = sni;
        }

        if (used_sni)
        {
            if (!SSL_set_tlsext_host_name(ssl, used_sni))
            {
                logOutputErrorConsoleCharString("connectTlsServer: Failed to set SNI extension");
                break;
            }
        }

        /* --- 绑定 socket --- */
        SSL_set_fd(ssl, socketInfo.fd);

        /* --- 执行 TLS 握手 --- */
        int sslConnect = SSL_connect(ssl);
        if (sslConnect <= 0)
        {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            char output_buf[512];
            snprintf(output_buf, sizeof(output_buf), "connectTlsServer: SSL_connect failed: %s", err_buf);
            logOutputErrorConsoleCharString(output_buf);
            break;
        }

        /* --- 客户端：验证服务端证书 --- */
        X509 *server_cert = SSL_get_peer_certificate(ssl);
        if (!server_cert)
        {
            logOutputErrorConsoleCharString("connectTlsServer: Server did not present a certificate");
            break;
        }

        // Verify result first (checks against CA list)
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK)
        {
            char err_buf[256];
            X509_verify_cert_error_string(verify_result);
            logOutputErrorConsoleCharString("connectTlsServer: Certificate verification failed:");
            logOutputErrorConsoleCharString(err_buf);
            X509_free(server_cert);
            break;
        }

        // Verify hostname
        if (!verify_cert_hostname(server_cert, verify_host))
        {
            logOutputErrorConsoleCharString("connectTlsServer: Certificate hostname verification failed.");
            logOutputErrorConsoleCharString("Expected Hostname: ");
            logOutputErrorConsoleCharString(verify_host);
            X509_free(server_cert);
            break;
        }
        X509_free(server_cert);

        logOutputInfoConsoleCharString("connectTlsServer: TLS handshake with remote server completed successfully.");

        // Log negotiated ALPN protocol
        const unsigned char *negotiated_proto = NULL;
        unsigned int proto_len = 0;
        SSL_get0_alpn_selected(ssl, &negotiated_proto, &proto_len);
        if (negotiated_proto && proto_len > 0)
        {
            char negotiated_protocol[20];
            snprintf(negotiated_protocol, sizeof(negotiated_protocol), "%.*s", proto_len, (char *)negotiated_proto);
            logOutputInfoConsoleCharString("ALPN: Negotiated ");
            logOutputInfoConsoleCharString(negotiated_protocol);
        }
        else
        {
            logOutputInfoConsoleCharString("ALPN: No protocol negotiated.");
        }

        /* --- 填充 client_info --- */
        client_info->fd = socketInfo.fd;
        client_info->ssl = ssl;
        client_info->ssl_ctx = clientTlsCtx; // 客户端上下文
        memcpy(&client_info->addr, &socketInfo.addr, socketInfo.addr_len);
        client_info->addr_len = socketInfo.addr_len;
        strncpy(client_info->ip_str, socketInfo.ip_str, sizeof(client_info->ip_str) - 1);
        client_info->ip_str[sizeof(client_info->ip_str) - 1] = '\0';
        client_info->port = socketInfo.port;

        return 0; // 成功

    } while (false); // 统一错误处理

    // 清理错误状态下的资源
    if (ssl)
    {
        SSL_free(ssl);
    }
    else if (temp_ctx)
    { // If SSL_new failed but CTX was created temporarily
        SSL_CTX_free(temp_ctx);
    }
    close(socketInfo.fd); // 关闭底层socket

    return -1; // 统一返回-1表示失败
}

// --- 清理资源函数 ---

/**
 * @brief 关闭并清理所有TLS相关资源。
 */
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

    // Modern OpenSSL (1.1.0+) manages most cleanup internally.
    // The following functions are often unnecessary or deprecated.
    // OPENSSL_cleanup() is the recommended way to clean up all OpenSSL resources.
    OPENSSL_cleanup();

    tlsInit = false;
    logOutputInfoConsoleCharString("All TLS resources cleaned up.");
}
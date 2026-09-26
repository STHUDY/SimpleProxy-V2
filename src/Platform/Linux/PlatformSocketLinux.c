#include "headfile.h"
#include "PlatformSocketLinux.h"

bool netWsaStartup(void)
{
    // Linux 的 socket 调用不需要任何库初始化
    return true;
}

void netWsaCleanup(void)
{
    // Linux 的 socket 调用不需要任何库清理
}

int netSocketClose(SOCKET_T fd)
{
    return close(fd);
}

int netShutdownBoth(SOCKET_T fd)
{
    return shutdown(fd, SHUT_RDWR);
}

int netSetRecvTimeoutMs(SOCKET_T fd, int timeoutMs)
{
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int netSetSendTimeoutMs(SOCKET_T fd, int timeoutMs)
{
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool netResolveIpv4(const char *host, struct sockaddr_in *addrOut)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    if (host == NULL || host[0] == '\0' || addrOut == NULL)
    {
        return false;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // 只取 IPv4，与原实现行为一致
    hints.ai_socktype = SOCK_STREAM;

    // getaddrinfo 同时覆盖点分十进制和主机名，省掉 inet_pton + gethostbyname 两段分支。
    // 原来的 gethostbyname 还要手动 memcpy h_addr_list[0]，且 h_length 类型与 socklen_t 不同。
    if (getaddrinfo(host, NULL, &hints, &result) != 0 || result == NULL)
    {
        return false;
    }

    // 只搬 sin_family 和 sin_addr，**不能整块 memcpy**：
    // getaddrinfo 返回的 sockaddr_in 里 sin_port 是 0（没传 service 名），
    // 整块覆盖会把调用方已经设好的端口清零，表现为连 0 端口失败。
    // 调用方约定：sin_port 由自己设置，这个函数不许碰。
    addrOut->sin_family = AF_INET;
    memcpy(&addrOut->sin_addr, &((struct sockaddr_in *)result->ai_addr)->sin_addr, sizeof(addrOut->sin_addr));

    freeaddrinfo(result);
    return true;
}

void *netAlignedAlloc(size_t size, size_t alignment)
{
    void *ptr = NULL;
    // posix_memalign 不要求 size 是 alignment 的整数倍
    if (posix_memalign(&ptr, alignment, size) != 0)
    {
        return NULL;
    }
    return ptr;
}

void netAlignedFree(void *ptr)
{
    free(ptr);
}

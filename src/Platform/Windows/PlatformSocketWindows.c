#include "headfile.h"
#include "PlatformSocketWindows.h"

bool netWsaStartup(void)
{
    WSADATA wsaData;

    // Winsock 必须先 WSAStartup，否则所有 socket 调用返回 WSANOTINITIALISED
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return false;
    }

    return true;
}

void netWsaCleanup(void)
{
    WSACleanup();
}

int netSocketClose(SOCKET_T fd)
{
    // 不能用 close：Windows 上 close 关的是 CRT 文件描述符，对 socket 无效
    return closesocket(fd);
}

int netShutdownBoth(SOCKET_T fd)
{
    // Winsock 没有 SHUT_RDWR，对应的常量是 SD_BOTH
    return shutdown(fd, SD_BOTH);
}

int netSetRecvTimeoutMs(SOCKET_T fd, int timeoutMs)
{
    // Windows 的 SO_RCVTIMEO 收 DWORD 毫秒数，不是 POSIX 的 struct timeval
    DWORD tv = (DWORD)timeoutMs;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
}

int netSetSendTimeoutMs(SOCKET_T fd, int timeoutMs)
{
    DWORD tv = (DWORD)timeoutMs;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
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

    // 用 getaddrinfo 而不是 gethostbyname：后者在 Windows 上已废弃，
    // 而且返回的 hostent 指向线程局部内存，跨线程使用不安全。
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
    // _aligned_malloc 不要求 size 是 alignment 的整数倍
    return _aligned_malloc(size, alignment);
}

void netAlignedFree(void *ptr)
{
    _aligned_free(ptr);
}

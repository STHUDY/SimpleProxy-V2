#include "headfile.h"
#include "PlatformErrorWindows.h"

int netLastError(void)
{
    // Windows 的 socket 错误不走 errno，errno 拿到的是 CRT 的 errno，没有意义
    return WSAGetLastError();
}

const char *netErrorString(int errCode)
{
    switch (errCode)
    {
    case WSAEINTR:
        return "Interrupted";
    case WSAEWOULDBLOCK:
        return "Resource temporarily unavailable";
    case WSAETIMEDOUT:
        return "Connection timed out";
    case WSAECONNRESET:
        return "Connection reset by peer";
    case WSAECONNABORTED:
        return "Software caused connection abort";
    case WSAECONNREFUSED:
        return "Connection refused";
    case WSAENOTCONN:
        return "Transport endpoint is not connected";
    case WSAEHOSTUNREACH:
        return "No route to host";
    case WSAENETUNREACH:
        return "Network is unreachable";
    case WSAENETDOWN:
        return "Network is down";
    case WSANOTINITIALISED:
        return "Winsock 库未初始化";
    case WSAEAFNOSUPPORT:
        return "Address family not supported by protocol";
    case WSAEADDRINUSE:
        return "Address already in use";
    case WSAEINVAL:
        return "Invalid argument";
    default:
    {
        // 未知错误码交给系统格式化。用线程局部缓冲，避免多 worker 互相覆盖。
        static __declspec(thread) char buffer[256];
        DWORD written = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                        NULL, (DWORD)errCode, 0, buffer, (DWORD)(sizeof(buffer) - 1), NULL);
        if (written == 0)
        {
            snprintf(buffer, sizeof(buffer), "unknown socket error %d", errCode);
        }
        else
        {
            buffer[written] = '\0';
            // FormatMessage 会在结尾补 "\r\n"，而日志那边还会再补一个换行，
            // 不裁掉的话每条未知错误码后面都会多出一个空行。
            while (written > 0 && (buffer[written - 1] == '\r' || buffer[written - 1] == '\n' || buffer[written - 1] == ' '))
            {
                buffer[--written] = '\0';
            }
            if (written == 0)
            {
                snprintf(buffer, sizeof(buffer), "unknown socket error %d", errCode);
            }
        }
        return buffer;
    }
    }
}

bool netIsWouldBlock(int errCode)
{
    // WSAETIMEDOUT 也要算在内：POSIX 上 SO_RCVTIMEO / SO_SNDTIMEO 到期返回的是 EAGAIN，
    // 调用方靠 netIsWouldBlock 认出"暂时没数据"并进入超时处理分支；
    // Windows 上同样的超时报的是 WSAETIMEDOUT，不加进来的话那些分支一个都进不去，
    // 连接会静默断开、丢掉超时日志。
    // 不会误伤忙循环：SO_RCVTIMEO 只在 readOrWriteTimeoutMs > 0 时才设，
    // 而那种配置下超时分支本来就会断开。
    return errCode == WSAEWOULDBLOCK || errCode == WSAETIMEDOUT;
}

bool netIsInterrupted(int errCode)
{
    return errCode == WSAEINTR;
}

bool netIsTimeout(int errCode)
{
    return errCode == WSAETIMEDOUT;
}

bool netIsReset(int errCode)
{
    return errCode == WSAECONNRESET;
}

bool netIsInProgress(int errCode)
{
    return errCode == WSAEWOULDBLOCK;
}

bool netIsAborted(int errCode)
{
    return errCode == WSAECONNABORTED;
}

bool netIsFdExhausted(int errCode)
{
    // Windows 没有每进程 fd 上限，句柄耗尽不会以 socket 错误码的形式出现
    (void)errCode;
    return false;
}

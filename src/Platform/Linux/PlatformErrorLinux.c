#include "headfile.h"
#include "PlatformErrorLinux.h"

int netLastError(void)
{
    // POSIX 的 socket 错误直接落在 errno 上
    return errno;
}

const char *netErrorString(int errCode)
{
    // strerror 对未知码可能带尾部换行（部分 glibc 版本会），统一裁掉，
    // 否则日志那边再补一个换行就会多出空行
    static __thread char fallback[256];

    switch (errCode)
    {
    // Linux 上 EWOULDBLOCK 就是 EAGAIN 的别名，不能同时写两个 case
    case EAGAIN:
        return "Resource temporarily unavailable";
    case EINTR:
        return "Interrupted system call";
    case EINPROGRESS:
        return "Operation now in progress";
    case ETIMEDOUT:
        return "Connection timed out";
    case ECONNRESET:
        return "Connection reset by peer";
    case EPIPE:
        return "Broken pipe";
    case ECONNABORTED:
        return "Software caused connection abort";
    case ECONNREFUSED:
        return "Connection refused";
    case ENOTCONN:
        return "Transport endpoint is not connected";
    case EHOSTUNREACH:
        return "No route to host";
    case ENETUNREACH:
        return "Network is unreachable";
    case EMFILE:
        return "Too many open files";
    case ENFILE:
        return "File table overflow";
    case EADDRINUSE:
        return "Address already in use";
    case EINVAL:
        return "Invalid argument";
    default:
    {
        const char *text = strerror(errCode);
        snprintf(fallback, sizeof(fallback), "%s", text != NULL ? text : "unknown socket error");
        size_t len = strlen(fallback);
        while (len > 0 && (fallback[len - 1] == '\r' || fallback[len - 1] == '\n' || fallback[len - 1] == ' '))
        {
            fallback[--len] = '\0';
        }
        return fallback;
    }
    }
}

bool netIsWouldBlock(int errCode)
{
    return errCode == EAGAIN || errCode == EWOULDBLOCK;
}

bool netIsInterrupted(int errCode)
{
    return errCode == EINTR;
}

bool netIsTimeout(int errCode)
{
    return errCode == ETIMEDOUT;
}

bool netIsReset(int errCode)
{
    return errCode == ECONNRESET || errCode == EPIPE;
}

bool netIsInProgress(int errCode)
{
    return errCode == EINPROGRESS;
}

bool netIsAborted(int errCode)
{
    return errCode == ECONNABORTED;
}

bool netIsFdExhausted(int errCode)
{
    return errCode == EMFILE || errCode == ENFILE;
}

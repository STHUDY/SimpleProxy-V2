#include "PlatformWaitWsapol.h"

// 代理每条连接最多同时等两个 fd（客户端 + 后端），留一点余量
#define PLATFORM_WAIT_MAX_FDS 8

struct PlatformWaitSet
{
    // WSAPoll 每次等待直接收 fd 数组，不需要预先登记，所以这里没有状态可存。
    // 保留字段是为了让两个平台的 PlatformWaitSet 形状一致。
    int reserved;
};

struct PlatformWaitSet *netWaitSetCreate(void)
{
    struct PlatformWaitSet *set = (struct PlatformWaitSet *)malloc(sizeof(struct PlatformWaitSet));
    if (set == NULL)
    {
        return NULL;
    }

    set->reserved = 0;
    return set;
}

int netWaitSetAdd(struct PlatformWaitSet *set, SOCKET_T fd)
{
    // Windows 的实现不需要登记 fd，netWaitSetWait 会直接收到 fd 数组。
    // 这里只做参数校验，让两个平台的调用行为一致。
    if (set == NULL || !netSocketValid(fd))
    {
        return -1;
    }

    return 0;
}

void netWaitSetDestroy(struct PlatformWaitSet *set)
{
    if (set == NULL)
    {
        return;
    }

    free(set);
}

int netWaitSetWait(struct PlatformWaitSet *set, int count, int wantWrite, int timeoutMs, SOCKET_T *fds, int *states)
{
    WSAPOLLFD pollFds[PLATFORM_WAIT_MAX_FDS];
    int readyNumber;
    int i;

    if (set == NULL || fds == NULL || states == NULL || count <= 0 || count > PLATFORM_WAIT_MAX_FDS)
    {
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        pollFds[i].fd = fds[i];
        // Windows 的 POLLRDNORM 是 0x0100、POLLWRNORM 是 0x0010，
        // 与 Linux 的 POLLIN 0x001 完全不是同一套编号，所以常量只能留在这里。
        pollFds[i].events = wantWrite ? POLLWRNORM : POLLRDNORM;
        pollFds[i].revents = 0;
        states[i] = NET_WAIT_NONE;
    }

    readyNumber = WSAPoll(pollFds, (ULONG)count, timeoutMs);
    if (readyNumber == SOCKET_ERROR)
    {
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        short revents = pollFds[i].revents;
        if (revents == 0)
        {
            continue;
        }

        // 先看等的方向，再看错误：对端正常关闭时 revents 会同时带读事件和挂断标志，
        // 必须让读事件先命中，才能走到 SSL_read 的干净关闭分支。
        if (revents & (wantWrite ? POLLWRNORM : POLLRDNORM))
        {
            states[i] = NET_WAIT_READY;
        }
        else if (revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            states[i] = NET_WAIT_FAILED;
        }
    }

    readyNumber = 0;
    for (i = 0; i < count; i++)
    {
        if (states[i] != NET_WAIT_NONE)
        {
            readyNumber++;
        }
    }

    return readyNumber;
}

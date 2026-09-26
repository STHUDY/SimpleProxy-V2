#include "headfile.h"
#include "PlatformWaitEpoll.h"

// 代理每条连接最多同时等两个 fd（客户端 + 后端），留一点余量
#define PLATFORM_WAIT_MAX_FDS 8

struct PlatformWaitSet
{
    int epollDescriptor;
};

struct PlatformWaitSet *netWaitSetCreate(void)
{
    struct PlatformWaitSet *set = (struct PlatformWaitSet *)malloc(sizeof(struct PlatformWaitSet));
    if (set == NULL)
    {
        return NULL;
    }

    set->epollDescriptor = epoll_create1(EPOLL_CLOEXEC);
    if (set->epollDescriptor < 0)
    {
        free(set);
        return NULL;
    }

    return set;
}

int netWaitSetAdd(struct PlatformWaitSet *set, SOCKET_T fd)
{
    struct epoll_event event;

    if (set == NULL || !netSocketValid(fd))
    {
        return -1;
    }

    memset(&event, 0, sizeof(event));
    // 水平触发：一次事件只做一次读或写，剩余数据会再次触发通知，
    // 不需要靠 SSL_pending 之类的手工排空。
    // 读和写一起注册，等哪个方向由 netWaitSetWait 的 wantWrite 决定，
    // 这样同一个 set 才能既等读又等写。
    event.events = EPOLLIN | EPOLLOUT;
    event.data.fd = fd;

    return epoll_ctl(set->epollDescriptor, EPOLL_CTL_ADD, fd, &event);
}

void netWaitSetDestroy(struct PlatformWaitSet *set)
{
    if (set == NULL)
    {
        return;
    }

    if (set->epollDescriptor >= 0)
    {
        close(set->epollDescriptor);
    }
    free(set);
}

int netWaitSetWait(struct PlatformWaitSet *set, int count, int wantWrite, int timeoutMs, SOCKET_T *fds, int *states)
{
    struct epoll_event events[PLATFORM_WAIT_MAX_FDS];
    int eventNumber;
    int readyNumber;
    int i;

    if (set == NULL || fds == NULL || states == NULL || count <= 0 || count > PLATFORM_WAIT_MAX_FDS)
    {
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        states[i] = NET_WAIT_NONE;
    }

    eventNumber = epoll_wait(set->epollDescriptor, events, count, timeoutMs);
    if (eventNumber == -1)
    {
        // 被信号打断按超时处理，交给上层重试，不当成错误
        if (errno == EINTR)
        {
            return 0;
        }
        return -1;
    }

    for (i = 0; i < eventNumber; i++)
    {
        int readyFd = events[i].data.fd;
        uint32_t flags = events[i].events;
        int j;

        for (j = 0; j < count; j++)
        {
            if (fds[j] != readyFd)
            {
                continue;
            }

            // 先看等的方向，再看错误：对端正常关闭时内核给的是 EPOLLIN|EPOLLRDHUP，
            // 必须让读事件先命中，才能走到 SSL_read 的干净关闭分支。
            if (wantWrite ? ((flags & EPOLLOUT) != 0) : ((flags & EPOLLIN) != 0))
            {
                states[j] = NET_WAIT_READY;
            }
            else if ((flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0)
            {
                states[j] = NET_WAIT_FAILED;
            }
            break;
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

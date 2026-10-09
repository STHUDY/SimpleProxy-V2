#include "PlatformWaitEpoll.h"

// 代理每条连接最多同时等两个 fd（客户端 + 后端），留一点余量
#define PLATFORM_WAIT_MAX_FDS 8

struct PlatformWaitSet
{
    int epollDescriptor;
    // 当前真正登记在 epoll 里的 fd，及其登记方向（0=EPOLLIN / 1=EPOLLOUT）。
    // netWaitSetWait 每次都要把这里对齐到"本次真正要等的 fd + 方向"。
    SOCKET_T registeredFds[PLATFORM_WAIT_MAX_FDS];
    int registeredWantWrite[PLATFORM_WAIT_MAX_FDS];
    int registeredCount;
};

// 在已登记列表里找 fd，返回下标；找不到返回 -1
static int findRegisteredFd(const struct PlatformWaitSet *set, SOCKET_T fd)
{
    int i;

    for (i = 0; i < set->registeredCount; i++)
    {
        if (set->registeredFds[i] == fd)
        {
            return i;
        }
    }

    return -1;
}

// 把 epoll 里登记的内容，对齐到"本次真正要等的 fd 集合 + 方向"。返回 0 成功，-1 失败。
//
// 为什么必须对齐：epoll 是按"登记的事件掩码"通知的，水平触发下条件只要还成立
// 每次都报。空闲的已连接 socket 发送缓冲区一直为空，也就是一直可写，
// 所以只要登记了 EPOLLOUT，epoll_wait 就会被立刻唤醒，永远等不到 timeoutMs。
// 主循环是 wantWrite=0（等读），却因为登记了 EPOLLOUT 而每轮空转一次，
// 返回 0（都没就绪）→ 调用方 continue → 再空转，worker 线程直接打满一个核。
//
// 只改方向不够：epoll_wait 会返回集合里任意一个就绪 fd，maxevents 只有 count，
// 别的 fd 的事件会被读进来却匹配不上 fds[0..count)，匹配不上就返回 0，
// 调用方同样当成"还没可写"立刻重试 —— 还是忙等。所以本次不等的 fd 要一并摘掉。
static int syncWaitRegistration(struct PlatformWaitSet *set, int count, int wantWrite, SOCKET_T *fds)
{
    struct epoll_event event;
    int i;
    int j;

    // 1) 本次要等的每个 fd，都登记成 wantWrite 这个方向
    for (i = 0; i < count; i++)
    {
        int index = findRegisteredFd(set, fds[i]);

        memset(&event, 0, sizeof(event));
        event.events = wantWrite ? EPOLLOUT : EPOLLIN;
        event.data.fd = fds[i];

        if (index < 0)
        {
            if (set->registeredCount >= PLATFORM_WAIT_MAX_FDS)
            {
                return -1;
            }
            if (epoll_ctl(set->epollDescriptor, EPOLL_CTL_ADD, fds[i], &event) < 0)
            {
                return -1;
            }
            set->registeredFds[set->registeredCount] = fds[i];
            set->registeredWantWrite[set->registeredCount] = wantWrite;
            set->registeredCount++;
        }
        else if (set->registeredWantWrite[index] != wantWrite)
        {
            if (epoll_ctl(set->epollDescriptor, EPOLL_CTL_MOD, fds[i], &event) < 0)
            {
                return -1;
            }
            set->registeredWantWrite[index] = wantWrite;
        }
    }

    // 2) 本次不等的 fd 摘掉。DEL 的返回值不检查：这是清理动作，
    //    而摘除一个已登记且仍打开的 fd 不会失败；真失败了对齐逻辑也只是
    //    多留一次冗余登记，下次同步会再摘一遍。
    for (i = 0; i < set->registeredCount;)
    {
        int stillWaiting = 0;

        for (j = 0; j < count; j++)
        {
            if (fds[j] == set->registeredFds[i])
            {
                stillWaiting = 1;
                break;
            }
        }

        if (stillWaiting)
        {
            i++;
            continue;
        }

        epoll_ctl(set->epollDescriptor, EPOLL_CTL_DEL, set->registeredFds[i], NULL);
        // 与末尾交换后删除，省掉数组前移
        set->registeredFds[i] = set->registeredFds[set->registeredCount - 1];
        set->registeredWantWrite[i] = set->registeredWantWrite[set->registeredCount - 1];
        set->registeredCount--;
    }

    return 0;
}

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

    set->registeredCount = 0;
    return set;
}

int netWaitSetAdd(struct PlatformWaitSet *set, SOCKET_T fd)
{
    struct epoll_event event;

    if (set == NULL || !netSocketValid(fd))
    {
        return -1;
    }

    if (findRegisteredFd(set, fd) >= 0)
    {
        // 已经登记过，不重复 ADD
        return 0;
    }

    if (set->registeredCount >= PLATFORM_WAIT_MAX_FDS)
    {
        return -1;
    }

    memset(&event, 0, sizeof(event));
    // 先按读方向登记，真正的方向由 netWaitSetWait 每次同步时对齐。
    // 这里绝不能一次登记 EPOLLIN|EPOLLOUT：空闲连接一直可写，
    // 水平触发下 EPOLLOUT 每轮都命中，epoll_wait 就退化成忙等。
    event.events = EPOLLIN;
    event.data.fd = fd;

    if (epoll_ctl(set->epollDescriptor, EPOLL_CTL_ADD, fd, &event) < 0)
    {
        return -1;
    }

    set->registeredFds[set->registeredCount] = fd;
    set->registeredWantWrite[set->registeredCount] = 0;
    set->registeredCount++;
    return 0;
}

void netWaitSetDestroy(struct PlatformWaitSet *set)
{
    if (set == NULL)
    {
        return;
    }

    // 关掉 epoll fd 会自动摘掉集合里所有 fd，不用逐个 DEL
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

    // 先对齐登记内容，再等。稳态下（同一批 fd、同一方向）这里不发任何系统调用。
    if (syncWaitRegistration(set, count, wantWrite, fds) == -1)
    {
        return -1;
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

// Windows 平台的事件等待接口，实现走 WSAPoll。
// 不写 include guard / #pragma once，不 include "headfile.h"：
// 可重复展开，只含前置声明与函数声明，不定义 struct / enum / 变量。
//
// 只前置声明、不写 typedef 的原因见 Linux/PlatformWaitEpoll.h。
//
// 注意 Windows 的 POLLIN 是 (POLLRDNORM | POLLRDBAND) = 0x0100|0x0200，
// 与 Linux 的 0x001 完全不同，所以事件常量只能留在各自实现里，
// 共享接口只暴露 wantWrite，不暴露事件标志位。

struct PlatformWaitSet;

#ifdef __cplusplus
extern "C"
{
#endif

struct PlatformWaitSet *netWaitSetCreate(void);
int netWaitSetAdd(struct PlatformWaitSet *set, SOCKET_T fd);
void netWaitSetDestroy(struct PlatformWaitSet *set);

// 等 fds[0..count) 中任一可读（wantWrite=0）或可写（wantWrite=1），最多 timeoutMs 毫秒。
// 返回就绪个数，0 表示超时，-1 表示出错。
// states[i] 取 NET_WAIT_NONE / NET_WAIT_READY / NET_WAIT_FAILED。
// fds 与 states 由调用方提供，长度都是 count。
int netWaitSetWait(struct PlatformWaitSet *set, int count, int wantWrite, int timeoutMs, SOCKET_T *fds, int *states);

#ifdef __cplusplus
}
#endif

// Linux 平台的互斥量接口，纯宏，不需要配套 .c。
// 不写 include guard / #pragma once，不 include 任何头：
// pthread.h 由 headfile.h 的 POSIX 分支提前引入。
//
// 为什么不直接用 PTHREAD_MUTEX_INITIALIZER：
// 原来的 rgLogOutputMutex / rgLogWriteFileMutex 从未显式初始化，
// 只是恰好 glibc 下全零值等于合法的普通互斥量。Windows 的 CRITICAL_SECTION
// 全零是非法的，EnterCriticalSection 会抛 STATUS_INVALID_CRITICAL_SECTION。
// 所以统一走显式 NET_MUTEX_INIT。

#define NET_MUTEX_T pthread_mutex_t

#define NET_MUTEX_INIT(mutex) pthread_mutex_init(&(mutex), NULL)
#define NET_MUTEX_DESTROY(mutex) pthread_mutex_destroy(&(mutex))
#define netMutexLock(mutex) pthread_mutex_lock(&(mutex))
#define netMutexUnlock(mutex) pthread_mutex_unlock(&(mutex))

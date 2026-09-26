// Windows 平台的互斥量接口，纯宏，不需要配套 .c。
// 不写 include guard / #pragma once，不 include 任何头：
// windows.h 由 headfile.h 的 _WIN32 分支提前引入。
//
// 这里必须显式 InitializeCriticalSection：全零的 CRITICAL_SECTION 是非法的，
// EnterCriticalSection 会抛 STATUS_INVALID_CRITICAL_SECTION。
// 原来的日志互斥量从来没有显式初始化过，只是在 glibc 下恰好能跑。

#define NET_MUTEX_T CRITICAL_SECTION

#define NET_MUTEX_INIT(mutex) InitializeCriticalSection(&(mutex))
#define NET_MUTEX_DESTROY(mutex) DeleteCriticalSection(&(mutex))
#define netMutexLock(mutex) EnterCriticalSection(&(mutex))
#define netMutexUnlock(mutex) LeaveCriticalSection(&(mutex))

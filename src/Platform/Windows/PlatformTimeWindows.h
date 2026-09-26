#ifndef __PLATFORM_TIME_WINDOWS_H__
#define __PLATFORM_TIME_WINDOWS_H__

// Windows 平台的本地时间接口，纯宏，不需要配套 .c。
// 不写 include guard / #pragma once，不 include 任何头：
// time.h 由 headfile.h 提前引入。
//
// MSVC 的 localtime_s 参数顺序是 (struct tm *, const time_t *)，与 POSIX 的
// localtime_r 一致，返回 0 表示成功。用它而不是 localtime：
// localtime 返回共享的静态 struct tm，多 worker 并发打日志会互相覆盖时间戳。
#ifdef __cplusplus
extern "C"
{
#endif

#define netLocalTime(tmPtr, timePtr) (localtime_s((tmPtr), (timePtr)) == 0)

#ifdef __cplusplus
}
#endif

#endif // __PLATFORM_TIME_WINDOWS_H__
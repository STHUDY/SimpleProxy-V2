#ifndef __PLATFORM_TIME_LINUX_H__
#define __PLATFORM_TIME_LINUX_H__
// Linux 平台的本地时间接口，纯宏，不需要配套 .c。
// 不写 include guard / #pragma once，不 include 任何头：
// time.h 由 headfile.h 提前引入。
//
// 用 localtime_r 而不是 localtime：localtime 返回共享的静态 struct tm，
// 多 worker 并发打日志会互相覆盖时间戳。

#ifdef __cplusplus
extern "C"
{
#endif

#define netLocalTime(tmPtr, timePtr) (localtime_r((timePtr), (tmPtr)) != NULL)

#ifdef __cplusplus
}
#endif

#endif
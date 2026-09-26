#ifndef __PLATFORM_ERROR_LINUX_H__
#define __PLATFORM_ERROR_LINUX_H__
#include "headfile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // 取最近一次 socket 调用的错误码
    int netLastError(void);

    // 错误码转可读字符串。已知错误码返回静态字符串，未知码回落到 strerror。
    // 返回的指针由调用方立即拷贝，不要长期持有。
    const char *netErrorString(int errCode);

    bool netIsWouldBlock(int errCode);
    bool netIsInterrupted(int errCode);
    bool netIsTimeout(int errCode);
    bool netIsReset(int errCode);
    // connect() 返回 EINPROGRESS 表示正在连接
    bool netIsInProgress(int errCode);
    // accept() 前的连接被客户端放弃
    bool netIsAborted(int errCode);
    // 进程 fd / 句柄耗尽
    bool netIsFdExhausted(int errCode);

#ifdef __cplusplus
}
#endif

#endif // __PLATFORM_ERROR_LINUX_H__
#ifndef __PLATFORM_ERROR_WINDOWS_H__
#define __PLATFORM_ERROR_WINDOWS_H__
#include "headfile.h"

// Windows 平台的 socket 错误码接口。
// 不写 include guard / #pragma once，不 include "headfile.h"。
// Windows 的 socket 错误不走 errno，而是 WSAGetLastError()，
// 且错误码与 POSIX 的 errno 不是同一套编号，谓词也必须分开判断。

#ifdef __cplusplus
extern "C"
{
#endif

// 取最近一次 socket 调用的错误码
int netLastError(void);

// 错误码转可读字符串。已知错误码返回静态字符串，未知码用 FormatMessage 生成。
// 返回的指针由调用方立即拷贝，不要长期持有。
const char *netErrorString(int errCode);

bool netIsWouldBlock(int errCode);
bool netIsInterrupted(int errCode);
bool netIsTimeout(int errCode);
bool netIsReset(int errCode);
// Winsock 的非阻塞 connect 返回 WSAEWOULDBLOCK 而不是 EINPROGRESS
bool netIsInProgress(int errCode);
// accept() 前的连接被客户端放弃
bool netIsAborted(int errCode);
// Windows 没有每进程 fd 上限，所以永远返回 false
bool netIsFdExhausted(int errCode);

#ifdef __cplusplus
}
#endif

#endif // __PLATFORM_ERROR_WINDOWS_H__

//=================C库=====================
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if defined(_WIN32)
// winsock2.h 必须排在 windows.h 前面：windows.h 会带入旧版 winsock.h 造成冲突
// （CMake 已定义 WIN32_LEAN_AND_MEAN，但这里显式包含更稳妥）
#include <winsock2.h>
#include <ws2tcpip.h> // inet_pton / inet_ntop / getaddrinfo
#include <windows.h>  // CRITICAL_SECTION
#include <malloc.h>   // _aligned_malloc / _aligned_free
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#endif
//=================C++库==================
#ifdef __cplusplus
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <queue>
#include <type_traits>
#include <utility>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <unordered_set>
#include <filesystem>
#include <sstream>
#include <new>
#endif
//==================用户C库================
// 平台兼容层必须排在 nSocket.h / nTls.h / config.h 之前：
// 它们要用到 SOCKET_T、netSocketValid、NET_MUTEX_T。
// src/Platform 下的头刻意不 include headfile.h，也不写 include guard，
// 靠的就是"全部从这里引入 + 内容可重复展开"这两条。
#include "PlatformBase.h"
#if defined(_WIN32)
#include "PlatformSocketWindows.h"
#include "PlatformErrorWindows.h"
#include "PlatformMutexWindows.h"
#include "PlatformTimeWindows.h"
#include "PlatformWaitWsapol.h"
#else
#include "PlatformSocketLinux.h"
#include "PlatformErrorLinux.h"
#include "PlatformMutexLinux.h"
#include "PlatformTimeLinux.h"
#include "PlatformWaitEpoll.h"
#endif
#include "nSocket.h"
#include "nTls.h"
#include "config.h"
#include "Log.h"
#include "define.h"
//================用户C++库=================
#ifdef __cplusplus
#include "ThreadpoolAutoCtrlByTime.hpp"
#include "config.hpp"
#include "Log.hpp"
#include "CallbackBase.hpp"
#include "SocketCallback.hpp"
#include "TlsCallback.hpp"
#endif

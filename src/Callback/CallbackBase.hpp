#pragma once

#include "headfile.h"

typedef struct CallbackShareInfo
{
    bool init;
    std::atomic<bool> close;
    float timeout;
    std::mutex *mutex;
} CallbackShareInfo;

// 选中的后端。host 归调用方所有（用 std::string 承载），
// 避免多线程共享同一个全局缓冲区导致 connect 读到被并发改写的目标。
struct BackendTarget
{
    std::string host;
    int port = 0;
};

bool isIpAllowed(const std::string &ip_str);

// 选一个后端写入 target；无可用后端时返回 false 且不修改 target
bool selectBackendTarget(BackendTarget &target);

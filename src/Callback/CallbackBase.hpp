#pragma once

#include "headfile.h"

typedef struct CallbackShareInfo
{
    bool init;
    bool close;
    float timeout;
    std::mutex *mutex;
} CallbackShareInfo;

bool isIpAllowed(const std::string &ip_str);

void selectBackendTarget();
#ifndef __LOG_H__
#define __LOG_H__

#include "headfile.h"

void logOutputErrorConsoleCharString(const char *msg);
void logOutputWarnConsoleCharString(const char *msg);
void logOutputInfoConsoleCharString(const char *msg);
void logOutputDebugConsoleCharString(const char *msg);

#endif
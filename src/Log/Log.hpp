#pragma once
#include "headfile.h"

void logOutputErrorConsole(const char *msg);
void logOutputErrorConsole(const std::string &msg);

void logOutputWarnConsole(const char *msg);
void logOutputWarnConsole(const std::string &msg);

void logOutputInfoConsole(const char *msg);
void logOutputInfoConsole(const std::string &msg);

void logOutputDebugConsole(const char *msg);
void logOutputDebugConsole(const std::string &msg);

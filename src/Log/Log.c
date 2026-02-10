#include "Log.h"

#define RESET "\033[0m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define GREEN "\033[32m"
#define BLUE "\033[34m"

char *getCurrentTimeString()
{
    static char time_str[100];
    time_t now = time(0);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

void logOutputErrorConsoleCharString(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 3)
    {
        const char *prefix = "[";
        const char *separator1 = "] [ERROR] ";
        const char *suffix = "\n";

        // 计算需要的缓冲区大小
        size_t len = strlen(prefix) + strlen(getCurrentTimeString()) + strlen(separator1) + strlen(msg) + strlen(suffix) + 1; // +1 for null terminator
        char *outputMsg = malloc(len);
        if (outputMsg == NULL)
        {
            // 内存分配失败，可以选择打印错误或直接返回
            return;
        }
        sprintf(outputMsg, "%s%s%s%s%s", prefix, getCurrentTimeString(), separator1, msg, suffix);

        if (LogEnbaleConsole)
        {
            printf("%s[%s] [ERROR] %s%s\n", RED, getCurrentTimeString(), msg, RESET);
            fflush(stdout);
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            if (LogFile != NULL)
            {                                      // 检查文件是否成功打开
                fprintf(LogFile, "%s", outputMsg); // outputMsg已经包含了换行符
                fflush(LogFile);
            }
            pthread_mutex_unlock(&LogMutex);
        }

        free(outputMsg); // 释放动态分配的内存
    }
}

void logOutputWarnConsoleCharString(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 2)
    {
        const char *prefix = "[";
        const char *separator1 = "] [WARN] ";
        const char *suffix = "\n";

        size_t len = strlen(prefix) + strlen(getCurrentTimeString()) + strlen(separator1) + strlen(msg) + strlen(suffix) + 1;
        char *outputMsg = malloc(len);
        if (outputMsg == NULL)
        {
            return;
        }
        sprintf(outputMsg, "%s%s%s%s%s", prefix, getCurrentTimeString(), separator1, msg, suffix);

        if (LogEnbaleConsole)
        {
            printf("%s[%s] [WARN] %s%s\n", YELLOW, getCurrentTimeString(), msg, RESET);
            fflush(stdout);
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            if (LogFile != NULL)
            {
                fprintf(LogFile, "%s", outputMsg);
                fflush(LogFile);
            }
            pthread_mutex_unlock(&LogMutex);
        }

        free(outputMsg);
    }
}

void logOutputInfoConsoleCharString(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 1)
    {
        const char *prefix = "[";
        const char *separator1 = "] [INFO] ";
        const char *suffix = "\n";

        size_t len = strlen(prefix) + strlen(getCurrentTimeString()) + strlen(separator1) + strlen(msg) + strlen(suffix) + 1;
        char *outputMsg = malloc(len);
        if (outputMsg == NULL)
        {
            return;
        }
        sprintf(outputMsg, "%s%s%s%s%s", prefix, getCurrentTimeString(), separator1, msg, suffix);

        if (LogEnbaleConsole)
        {
            printf("%s[%s] [INFO] %s%s\n", GREEN, getCurrentTimeString(), msg, RESET);
            fflush(stdout);
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            if (LogFile != NULL)
            {
                fprintf(LogFile, "%s", outputMsg);
                fflush(LogFile);
            }
            pthread_mutex_unlock(&LogMutex);
        }

        free(outputMsg);
    }
}

void logOutputDebugConsoleCharString(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 0)
    {
        const char *prefix = "[";
        const char *separator1 = "] [DEBUG] ";
        const char *suffix = "\n";

        size_t len = strlen(prefix) + strlen(getCurrentTimeString()) + strlen(separator1) + strlen(msg) + strlen(suffix) + 1;
        char *outputMsg = malloc(len);
        if (outputMsg == NULL)
        {
            return;
        }
        sprintf(outputMsg, "%s%s%s%s%s", prefix, getCurrentTimeString(), separator1, msg, suffix);

        if (LogEnbaleConsole)
        {
            printf("%s[%s] [DEBUG] %s%s\n", BLUE, getCurrentTimeString(), msg, RESET);
            fflush(stdout);
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            if (LogFile != NULL)
            {
                fprintf(LogFile, "%s", outputMsg);
                fflush(LogFile);
            }
            pthread_mutex_unlock(&LogMutex);
        }

        free(outputMsg);
    }
}

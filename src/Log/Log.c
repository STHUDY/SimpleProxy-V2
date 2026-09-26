#include "Log.h"

// 颜色定义
#define DEBUG_COLOR "\033[0;34m" // 蓝色
#define INFO_COLOR "\033[0;32m"  // 绿色
#define WARN_COLOR "\033[0;33m"  // 黄色
#define ERROR_COLOR "\033[0;31m" // 红色
#define FATAL_COLOR "\033[0;35m" // 紫色
#define RESET_COLOR "\033[0m"

// 格式化当前时间到调用方缓冲区。
// 用 localtime_r 而不是 localtime：后者返回共享静态存储，多线程会互相覆盖；
// 时间戳也不能放 static 缓冲，否则同样会被别的线程写掉。
static void formatCurrentTime(char *buf, size_t len)
{
    time_t now = time(0);
    struct tm tm_info;
    if (!netLocalTime(&tm_info, &now))
    {
        snprintf(buf, len, "0000-00-00 00:00:00");
        return;
    }
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_info);
}

// 辅助函数：写入文件（线程安全）
static void writeToFile(const char *level, const char *msg)
{
    if (!gConfigLogEnbaleFile)
        return;

    char timeStr[100];
    formatCurrentTime(timeStr, sizeof(timeStr));

    // 行缓冲放在栈上并在锁内拼装，避免多线程串行化时内容互相覆盖
    char outputMsg[2048];
    snprintf(outputMsg, sizeof(outputMsg), "[%s] [%s] %s", timeStr, level, msg);

    netMutexLock(rgLogWriteFileMutex);
    if (rgLogFileOpen == NULL)
    {
        rgLogFileOpen = fopen(gConfigLogFileChar, "a");
        if (rgLogFileOpen == NULL)
        {
            gConfigLogEnbaleFile = false;
            netMutexUnlock(rgLogWriteFileMutex);
            // 直接输出到 stderr（避免递归）
            fprintf(stderr, "[%s] [ERROR] open log file error: %s will not write log to file\n",
                    timeStr, strerror(errno));
            return;
        }
    }
    fprintf(rgLogFileOpen, "%s\n", outputMsg);
    fflush(rgLogFileOpen);
    netMutexUnlock(rgLogWriteFileMutex);
}

// ---------- FATAL ----------
void logOutputFatalConsole(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_FATAL)
    {
        if (gConfigLogEnbaleConsole)
        {
            char timeStr[100];
            formatCurrentTime(timeStr, sizeof(timeStr));
            netMutexLock(rgLogOutputMutex);
            printf(FATAL_COLOR "[%s] [FATAL] %s" RESET_COLOR "\n", timeStr, msg);
            netMutexUnlock(rgLogOutputMutex);
        }
        writeToFile("FATAL", msg);
    }
}

// ---------- ERROR ----------
void logOutputErrorConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_ERROR)
    {
        if (gConfigLogEnbaleConsole)
        {
            char timeStr[100];
            formatCurrentTime(timeStr, sizeof(timeStr));
            netMutexLock(rgLogOutputMutex);
            printf(ERROR_COLOR "[%s] [ERROR] %s" RESET_COLOR "\n", timeStr, msg);
            netMutexUnlock(rgLogOutputMutex);
        }
        writeToFile("ERROR", msg);
    }
}

// ---------- WARN ----------
void logOutputWarnConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_WARN)
    {
        if (gConfigLogEnbaleConsole)
        {
            char timeStr[100];
            formatCurrentTime(timeStr, sizeof(timeStr));
            netMutexLock(rgLogOutputMutex);
            printf(WARN_COLOR "[%s] [WARN] %s" RESET_COLOR "\n", timeStr, msg);
            netMutexUnlock(rgLogOutputMutex);
        }
        writeToFile("WARN", msg);
    }
}

// ---------- INFO ----------
void logOutputInfoConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_INFO)
    {
        if (gConfigLogEnbaleConsole)
        {
            char timeStr[100];
            formatCurrentTime(timeStr, sizeof(timeStr));
            netMutexLock(rgLogOutputMutex);
            printf(INFO_COLOR "[%s] [INFO] %s" RESET_COLOR "\n", timeStr, msg);
            netMutexUnlock(rgLogOutputMutex);
        }
        writeToFile("INFO", msg);
    }
}

// ---------- DEBUG ----------
void logOutputDebugConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_DEBUG)
    {
        if (gConfigLogEnbaleConsole)
        {
            char timeStr[100];
            formatCurrentTime(timeStr, sizeof(timeStr));
            netMutexLock(rgLogOutputMutex);
            printf(DEBUG_COLOR "[%s] [DEBUG] %s" RESET_COLOR "\n", timeStr, msg);
            netMutexUnlock(rgLogOutputMutex);
        }
        writeToFile("DEBUG", msg);
    }
}
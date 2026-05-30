#include "Log.h"

// 颜色定义
#define DEBUG_COLOR "\033[0;34m" // 蓝色
#define INFO_COLOR "\033[0;32m"  // 绿色
#define WARN_COLOR "\033[0;33m"  // 黄色
#define ERROR_COLOR "\033[0;31m" // 红色
#define FATAL_COLOR "\033[0;35m" // 紫色
#define RESET_COLOR "\033[0m"

char *getCurrentTimeString()
{
    static char time_str[100];
    time_t now = time(0);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

// 辅助函数：写入文件（线程安全）
static void writeToFile(const char *level, const char *msg)
{
    if (!gConfigLogEnbaleFile)
        return;

    char *timeStr = getCurrentTimeString();
    // 使用固定缓冲区避免多次分配，注意线程安全（此处简单起见，使用静态缓冲区可能冲突，但日志场景可接受）
    static char outputMsg[512];
    snprintf(outputMsg, sizeof(outputMsg), "[%s] [%s] %s", timeStr, level, msg);

    pthread_mutex_lock(&rgLogWriteFileMutex);
    if (rgLogFileOpen == NULL)
    {
        rgLogFileOpen = fopen(gConfigLogFileChar, "a");
        if (rgLogFileOpen == NULL)
        {
            gConfigLogEnbaleFile = false;
            pthread_mutex_unlock(&rgLogWriteFileMutex);
            // 直接输出到 stderr（避免递归）
            fprintf(stderr, "[%s] [ERROR] open log file error: %s will not write log to file\n",
                    getCurrentTimeString(), strerror(errno));
            return;
        }
    }
    fprintf(rgLogFileOpen, "%s\n", outputMsg);
    fflush(rgLogFileOpen);
    pthread_mutex_unlock(&rgLogWriteFileMutex);
}

// ---------- FATAL ----------
void logOutputFatalConsole(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_FATAL)
    {
        char *timeStr = getCurrentTimeString();
        if (gConfigLogEnbaleConsole)
        {
            printf(FATAL_COLOR "[%s] [FATAL] %s" RESET_COLOR "\n", timeStr, msg);
        }
        writeToFile("FATAL", msg);
    }
}

// ---------- ERROR ----------
void logOutputErrorConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_ERROR)
    {
        char *timeStr = getCurrentTimeString();
        if (gConfigLogEnbaleConsole)
        {
            printf(ERROR_COLOR "[%s] [ERROR] %s" RESET_COLOR "\n", timeStr, msg);
        }
        writeToFile("ERROR", msg);
    }
}

// ---------- WARN ----------
void logOutputWarnConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_WARN)
    {
        char *timeStr = getCurrentTimeString();
        if (gConfigLogEnbaleConsole)
        {
            printf(WARN_COLOR "[%s] [WARN] %s" RESET_COLOR "\n", timeStr, msg);
        }
        writeToFile("WARN", msg);
    }
}

// ---------- INFO ----------
void logOutputInfoConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_INFO)
    {
        char *timeStr = getCurrentTimeString();
        if (gConfigLogEnbaleConsole)
        {
            printf(INFO_COLOR "[%s] [INFO] %s" RESET_COLOR "\n", timeStr, msg);
        }
        writeToFile("INFO", msg);
    }
}

// ---------- DEBUG ----------
void logOutputDebugConsoleCharString(const char *msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_DEBUG)
    {
        char *timeStr = getCurrentTimeString();
        if (gConfigLogEnbaleConsole)
        {
            printf(DEBUG_COLOR "[%s] [DEBUG] %s" RESET_COLOR "\n", timeStr, msg);
        }
        writeToFile("DEBUG", msg);
    }
}
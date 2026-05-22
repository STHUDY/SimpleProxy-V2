#include "Log.hpp"

// ANSI颜色代码
const std::string DEBUG_COLOR = "\033[0;32m"; // 绿色
const std::string INFO_COLOR = "\033[0;34m";  // 蓝色
const std::string WARN_COLOR = "\033[0;33m";  // 黄色
const std::string ERROR_COLOR = "\033[0;31m"; // 红色
const std::string FATAL_COLOR = "\033[0;35m"; // 紫色
const std::string RESET_COLOR = "\033[0m";

// 获取当前时间字符串
std::string getCurrentTime()
{
    static char time_str[100];
    time_t now = time(0);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

// 内部辅助函数：写入文件（线程安全）
static void writeToFile(const std::string &level, const std::string &msg)
{
    if (!gConfigLogEnbaleFile)
        return;

    std::string outputMsg = "[" + getCurrentTime() + "] [" + level + "] " + msg;

    pthread_mutex_lock(&rgLogWriteFileMutex);
    if (rgLogFileOpen == NULL)
    {
        rgLogFileOpen = fopen(gConfigLogFileChar, "a");
        if (rgLogFileOpen == NULL)
        {
            // 无法打开文件，禁用文件日志并输出错误到控制台（避免递归）
            gConfigLogEnbaleFile = false;
            pthread_mutex_unlock(&rgLogWriteFileMutex);

            // 直接输出到控制台（不使用文件日志，防止递归）
            std::cerr << "[" << getCurrentTime() << "] [ERROR] "
                      << "open log file error: " << strerror(errno)
                      << " will not write log to file" << std::endl;
            return;
        }
    }
    fprintf(rgLogFileOpen, "%s\n", outputMsg.c_str());
    fflush(rgLogFileOpen);
    pthread_mutex_unlock(&rgLogWriteFileMutex);
}

// ---------- FATAL ----------
void logOutputFatalConsole(const char *msg)
{
    logOutputFatalConsole(std::string(msg));
}

void logOutputFatalConsole(const std::string &msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_FATAL)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [FATAL] " + msg;
        if (gConfigLogEnbaleConsole)
        {
            std::cout << FATAL_COLOR << outputMsg << RESET_COLOR << std::endl;
        }
        writeToFile("FATAL", msg);
    }
}

// ---------- ERROR ----------
void logOutputErrorConsole(const char *msg)
{
    logOutputErrorConsole(std::string(msg));
}

void logOutputErrorConsole(const std::string &msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_ERROR)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [ERROR] " + msg;
        if (gConfigLogEnbaleConsole)
        {
            std::cout << ERROR_COLOR << outputMsg << RESET_COLOR << std::endl;
        }
        writeToFile("ERROR", msg);
    }
}

// ---------- WARN ----------
void logOutputWarnConsole(const char *msg)
{
    logOutputWarnConsole(std::string(msg));
}

void logOutputWarnConsole(const std::string &msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_WARN)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [WARN] " + msg;
        if (gConfigLogEnbaleConsole)
        {
            std::cout << WARN_COLOR << outputMsg << RESET_COLOR << std::endl;
        }
        writeToFile("WARN", msg);
    }
}

// ---------- INFO ----------
void logOutputInfoConsole(const char *msg)
{
    logOutputInfoConsole(std::string(msg));
}

void logOutputInfoConsole(const std::string &msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_INFO)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [INFO] " + msg;
        if (gConfigLogEnbaleConsole)
        {
            std::cout << INFO_COLOR << outputMsg << RESET_COLOR << std::endl;
        }
        writeToFile("INFO", msg);
    }
}

// ---------- DEBUG ----------
void logOutputDebugConsole(const char *msg)
{
    logOutputDebugConsole(std::string(msg));
}

void logOutputDebugConsole(const std::string &msg)
{
    if (gConfigLogEnbale && gConfigLogLevel <= LOG_LEVEL_DEBUG)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [DEBUG] " + msg;
        if (gConfigLogEnbaleConsole)
        {
            std::cout << DEBUG_COLOR << outputMsg << RESET_COLOR << std::endl;
        }
        writeToFile("DEBUG", msg);
    }
}
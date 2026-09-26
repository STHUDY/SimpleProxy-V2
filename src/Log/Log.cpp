#include "Log.hpp"

// ANSI颜色代码
const std::string DEBUG_COLOR = "\033[0;34m"; // 蓝色
const std::string INFO_COLOR = "\033[0;32m";  // 绿色
const std::string WARN_COLOR = "\033[0;33m";  // 黄色
const std::string ERROR_COLOR = "\033[0;31m"; // 红色
const std::string FATAL_COLOR = "\033[0;35m"; // 紫色
const std::string RESET_COLOR = "\033[0m";

// 获取当前时间字符串。
// 用 localtime_r + 调用方缓冲区：原先的 static 缓冲 + localtime()
// 会让多线程日志互相覆盖时间戳。
static std::string getCurrentTime()
{
    char time_str[100];
    time_t now = time(0);
    struct tm tm_info;
    if (!netLocalTime(&tm_info, &now))
    {
        return std::string("0000-00-00 00:00:00");
    }
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    return std::string(time_str);
}

// 内部辅助函数：写入文件（线程安全）
static void writeToFile(const std::string &level, const std::string &msg)
{
    if (!gConfigLogEnbaleFile)
        return;

    std::string outputMsg = "[" + getCurrentTime() + "] [" + level + "] " + msg;

    netMutexLock(rgLogWriteFileMutex);
    if (rgLogFileOpen == NULL)
    {
        rgLogFileOpen = fopen(gConfigLogFileChar, "a");
        if (rgLogFileOpen == NULL)
        {
            // 无法打开文件，禁用文件日志并输出错误到控制台（避免递归）
            gConfigLogEnbaleFile = false;
            netMutexUnlock(rgLogWriteFileMutex);

            // 直接输出到控制台（不使用文件日志，防止递归）
            std::cerr << "[" << getCurrentTime() << "] [ERROR] "
                      << "open log file error: " << strerror(errno)
                      << " will not write log to file" << std::endl;
            return;
        }
    }
    fprintf(rgLogFileOpen, "%s\n", outputMsg.c_str());
    fflush(rgLogFileOpen);
    netMutexUnlock(rgLogWriteFileMutex);
}

// 控制台输出加锁，保证时间戳与正文不被其它线程的输出穿插
static void outputConsole(const std::string &color, const std::string &level, const std::string &msg)
{
    std::string outputMsg = "[" + getCurrentTime() + "] [" + level + "] " + msg;
    netMutexLock(rgLogOutputMutex);
    std::cout << color << outputMsg << RESET_COLOR << std::endl;
    netMutexUnlock(rgLogOutputMutex);
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
        if (gConfigLogEnbaleConsole)
        {
            outputConsole(FATAL_COLOR, "FATAL", msg);
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
        if (gConfigLogEnbaleConsole)
        {
            outputConsole(ERROR_COLOR, "ERROR", msg);
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
        if (gConfigLogEnbaleConsole)
        {
            outputConsole(WARN_COLOR, "WARN", msg);
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
        if (gConfigLogEnbaleConsole)
        {
            outputConsole(INFO_COLOR, "INFO", msg);
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
        if (gConfigLogEnbaleConsole)
        {
            outputConsole(DEBUG_COLOR, "DEBUG", msg);
        }
        writeToFile("DEBUG", msg);
    }
}
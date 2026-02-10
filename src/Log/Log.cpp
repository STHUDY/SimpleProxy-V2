#include "Log.hpp"

// ANSI颜色代码
const std::string RESET = "\033[0m";
const std::string RED = "\033[31m";
const std::string YELLOW = "\033[33m";
const std::string GREEN = "\033[32m";
const std::string BLUE = "\033[34m";

std::string getCurrentTime()
{
    static char time_str[100];
    time_t now = time(0);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

void logOutputErrorConsole(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 3)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [ERROR] " + std::string(msg);

        if (LogEnbaleConsole)
        {
            std::cout << RED << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputErrorConsole(const std::string &msg)
{
    if (LogEnbale && LogLevelNumber <= 3)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [ERROR] " + msg;

        if (LogEnbaleConsole)
        {
            std::cout << RED << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputWarnConsole(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 2)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [WARN] " + std::string(msg);

        if (LogEnbaleConsole)
        {
            std::cout << YELLOW << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputWarnConsole(const std::string &msg)
{
    if (LogEnbale && LogLevelNumber <= 2)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [WARN] " + msg;

        if (LogEnbaleConsole)
        {
            std::cout << YELLOW << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputInfoConsole(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 1)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [INFO] " + std::string(msg);

        if (LogEnbaleConsole)
        {
            std::cout << GREEN << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputInfoConsole(const std::string &msg)
{
    if (LogEnbale && LogLevelNumber <= 1)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [INFO] " + msg;

        if (LogEnbaleConsole)
        {
            std::cout << GREEN << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputDebugConsole(const char *msg)
{
    if (LogEnbale && LogLevelNumber <= 0)
    {
        // 构建统一的消息字符串
        std::string outputMsg = "[" + getCurrentTime() + "] [DEBUG] " + std::string(msg);

        if (LogEnbaleConsole)
        {
            std::cout << BLUE << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

void logOutputDebugConsole(const std::string &msg)
{
    if (LogEnbale && LogLevelNumber <= 0)
    {
        std::string outputMsg = "[" + getCurrentTime() + "] [DEBUG] " + msg;

        if (LogEnbaleConsole)
        {
            std::cout << BLUE << outputMsg << RESET << std::endl;
        }

        if (LogFilePathChar != NULL) // 写入文件日志
        {
            pthread_mutex_lock(&LogMutex);
            if (LogFile == NULL)
            {
                LogFile = fopen(LogFilePathChar, "a");
            }
            fprintf(LogFile, "%s\n", outputMsg.c_str());
            fflush(LogFile);
            pthread_mutex_unlock(&LogMutex);
        }
    }
}

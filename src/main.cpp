#include "headfile.h"
#include <sys/resource.h>  // 添加rlimit相关的头文件

bool SigintFlag = false;

void SigintHandler(int sig)
{
    SigintFlag = true;
    std::cout << " Ctrl+C pressed: wait close" << std::endl;
}

// 设置文件描述符限制
void setFileDescriptorLimit()
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        logOutputInfoConsole("Current file descriptor limit: " + std::to_string(rl.rlim_cur) + "/" + std::to_string(rl.rlim_max));
        
        // 如果当前限制太低，尝试提高到合理值
        if (rl.rlim_cur < 65536) {
            rl.rlim_cur = std::min(static_cast<rlim_t>(65536), rl.rlim_max);
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                logOutputInfoConsole("Increased file descriptor limit to: " + std::to_string(rl.rlim_cur));
            } else {
                logOutputWarnConsole("Failed to increase file descriptor limit: " + std::string(strerror(errno)));
            }
        }
    } else {
        logOutputErrorConsole("Failed to get file descriptor limit: " + std::string(strerror(errno)));
    }
}

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa;
    sa.sa_handler = SigintHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        logOutputWarnConsole("[WARN] sigaction error but it is not improtant");
    }

    // 设置文件描述符限制
    setFileDescriptorLimit();

    try
    {

        std::string configFile = "./config.yml";

        if (argc > 1) // 至少有一个额外参数
        {
            if (strcmp(argv[1], "-c") == 0)
            {
                if (argc > 2) // 确保有配置文件参数
                {
                    logOutputInfoConsole("using config file: " + std::string(argv[2]));
                    configFile = argv[2];
                }
                else
                {
                    logOutputErrorConsole("Missing config file path after -c option");
                    std::cout << "Usage: " << argv[0] << " -c [config file]" << std::endl;
                    return EXIT_FAILURE;
                }
            }
            else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
            {
                std::cout << "Usage: " << std::endl
                          << "   -c [config file]" << std::endl;
                return EXIT_SUCCESS;
            }
            else
            {
                logOutputErrorConsole("Unknown option: " + std::string(argv[1]));
                std::cout << "Usage: " << std::endl
                          << "   -c [config file]" << std::endl;
                return EXIT_FAILURE;
            }
        }
        YAML::Node config = YAML::LoadFile(configFile);

        ConnectTimeout = config["config"]["timeout"].as<int>();
        PollingIntervalMs = config["config"]["pollingIntervalMs"].as<int>();

        LogEnbale = config["config"]["log"]["enable"].as<bool>();
        LogEnbaleConsole = config["config"]["log"]["console"].as<bool>();
        LogLevel = config["config"]["log"]["level"].as<std::string>();
        if (LogLevel == "debug")
        {
            LogLevelNumber = 0;
        }
        else if (LogLevel == "info")
        {
            LogLevelNumber = 1;
        }
        else if (LogLevel == "warn")
        {
            LogLevelNumber = 2;
        }
        else if (LogLevel == "error")
        {
            LogLevelNumber = 3;
        }

        std::string logFilePathStr = config["config"]["log"]["filePath"].as<std::string>();
        if (logFilePathStr.empty())
        {
            LogFilePathChar = NULL;
        }
        else
        {
            std::filesystem::path logPath(logFilePathStr);
            if (std::filesystem::exists(logPath) ||
                std::filesystem::exists(logPath.parent_path()))
            {

                LogFilePath = logFilePathStr;                              // 存储原始 string
                LogFilePathChar = const_cast<char *>(LogFilePath.c_str()); // 转换为 char*
            }
            else
            {
                logOutputWarnConsole("[WARN] Log file path or its parent directory does not exist");
                LogFilePath = "";
                LogFilePathChar = NULL;
            }
        }

        ThreadPoolMaxThreadNumber = config["config"]["threadPool"]["maxWokers"].as<size_t>() + 5;
        ThreadPoolMinThreadNumber = config["config"]["threadPool"]["minWokers"].as<size_t>() + 5;
        ThreadPoolClearThreadTimeMs = config["config"]["threadPool"]["clearThreadTimeMs"].as<int>();
        ThreadPoolWaitTimeMs = config["config"]["threadPool"]["waitTimeMs"].as<int>();
        ThreadPoolStepAddThreadNumber = config["config"]["threadPool"]["stepAddThreadNumber"].as<int>();

        logOutputInfoConsole("load config file success");

        serverHost = config["server"]["host"].as<std::string>();
        serverHostChar = (char *)serverHost.c_str();

        serverPort = config["server"]["port"].as<int>();

        clientHost = config["client"]["host"].as<std::string>();
        clientHostChar = (char *)clientHost.c_str();

        clientPort = config["client"]["port"].as<int>();

        serverSocketBufferSize = config["server"]["socket"]["bufferSize"].as<int>();
        serverSocketMaxBacklog = config["server"]["socket"]["maxBacklog"].as<int>();

        TlsEnbale = config["config"]["tls"]["enable"].as<bool>();
        TlsNoBlock = config["config"]["tls"]["noBlock"].as<bool>();
        TlsNoBlockConnect = config["config"]["tls"]["noBlockConnect"].as<bool>();

        SocketEnableSync = config["config"]["socket"]["enableSync"].as<bool>();
        SocketNoBlockConnect = config["config"]["socket"]["noBlockConnect"].as<bool>();

        tlsCertFile = config["server"]["tls"]["cert"].as<std::string>();
        tlsCertFileChar = (char *)tlsCertFile.c_str();
        tlsKeyFile = config["server"]["tls"]["key"].as<std::string>();
        tlsKeyFileChar = (char *)tlsKeyFile.c_str();

        clientSocketBufferSize = config["client"]["socket"]["bufferSize"].as<int>();
        tlsClientHostName = config["client"]["tls"]["hostname"].as<std::string>();
        if (tlsClientHostName != "")
        {
            tlsClientHostNameChar = (char *)tlsClientHostName.c_str();
        }
        tlsClientSni = config["client"]["tls"]["sni"].as<std::string>();
        if (tlsClientSni != "")
        {
            tlsClientSniChar = (char *)tlsClientSni.c_str();
        }

        tlsServerCaFile = config["client"]["tls"]["caCert"].as<std::string>();
        if (tlsServerCaFile != "")
        {
            tlsServerCaFileChar = (char *)tlsServerCaFile.c_str();
        }

        YAML::Node banList = config["server"]["connect"]["banIps"];
        YAML::Node allowList = config["server"]["connect"]["allowedIps"];

        for (const auto &item : banList)
        {
            if (item.IsScalar())
            { // 检查是否为标量值
                std::string value = item.as<std::string>();
                banIpList.push_back(value);
            }
        }

        for (const auto &item : allowList)
        {
            if (item.IsScalar())
            { // 检查是否为标量值
                std::string value = item.as<std::string>();
                allowIpList.push_back(value);
                logOutputInfoConsole("Firewall: Allow IP added - " + value);
            }
        }
        
        // 记录防火墙配置摘要
        if (!banIpList.empty() || !allowIpList.empty()) {
            logOutputInfoConsole("Firewall configured - Banned IPs: " + std::to_string(banIpList.size()) + 
                               ", Allowed IPs: " + std::to_string(allowIpList.size()));
        } else {
            logOutputWarnConsole("Firewall disabled - all IPs are allowed");
        }
    }
    catch (YAML::Exception &e)
    {
        std::string error = "Configuration error in config.yml: ";
        error.append(e.what());
        logOutputErrorConsole(error);
        return EXIT_FAILURE;
    }

    if (TlsNoBlock == false && TlsEnbale)
    {
        if (clientSocketBufferSize < 8192)
        {
            logOutputWarnConsole("Performance warning: In blocking TLS mode, clientSocketBufferSize (" + std::to_string(clientSocketBufferSize) + ") is smaller than recommended minimum (8192). Consider increasing it.");
        }
        if (serverSocketBufferSize < 8192)
        {
            logOutputWarnConsole("Performance warning: In blocking TLS mode, serverSocketBufferSize (" + std::to_string(serverSocketBufferSize) + ") is smaller than recommended minimum (8192). Consider increasing it.");
        }
    }

    logOutputInfoConsole("ThreadPool configured - Min: " + std::to_string(ThreadPoolMinThreadNumber) + 
                        ", Max: " + std::to_string(ThreadPoolMaxThreadNumber) + 
                        ", Clear interval: " + std::to_string(ThreadPoolClearThreadTimeMs) + "ms");

    threadPool.setMinThreadNumber(ThreadPoolMinThreadNumber);
    threadPool.setMaxThreadNumber(ThreadPoolMaxThreadNumber);
    threadPool.setClearThreadTimeMs(ThreadPoolClearThreadTimeMs);
    threadPool.setWaitTimeMs(ThreadPoolWaitTimeMs);
    threadPool.setStepAddThreadNumber(ThreadPoolStepAddThreadNumber);

    if (TlsEnbale)
    {
        logOutputInfoConsole("Initializing TLS server mode...");
        initTlsServer();
    }
    else
    {
        logOutputInfoConsole("Initializing plain socket server mode...");
        initSocketServer();
    }

    if (socketServerFd < 0)
    {
        logOutputErrorConsole("Failed to initialize server socket");
        return EXIT_FAILURE;
    }

    threadPool.init();

    if (TlsEnbale)
    {
        threadPool.submitMission(tlsListenerCallback);
        logOutputInfoConsole("TLS server started successfully on " + serverHost + ":" + std::to_string(serverPort));
    }
    else
    {
        threadPool.submitMission(socketListenerCallback);
        logOutputInfoConsole("Plain socket server started successfully on " + serverHost + ":" + std::to_string(serverPort));
    }

    while (!SigintFlag)
    {
        std::string cmd;
        std::cin >> cmd;
        if (cmd == "exit")
        {
            logOutputInfoConsole("server exit");
            break;
        }

        // wait 1 s
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (TlsEnbale)
    {
        closeTlsServer();
        threadPool.waitMissionDone();
        threadPool.shutdown();
        closeTlsResource();
    }
    else
    {
        closeSocketServer();
        threadPool.waitMissionDone();
        threadPool.shutdown();
    }

    if (LogFile != NULL)
    {
        fclose(LogFile);
        LogFile = NULL;
    }

    return EXIT_SUCCESS;
}

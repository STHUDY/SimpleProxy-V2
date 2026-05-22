#include "headfile.h"

bool SigintFlag = false;
void SigintHandler(int sig)
{
    SigintFlag = true;
    std::cout << " Ctrl+C pressed: wait close" << std::endl;
}

int chooseConnectUseIoMode(std::string connectUseIoModeString)
{
    if (connectUseIoModeString == "none")
    {
        return CONNECT_USE_IO_NONE;
    }
    else if (connectUseIoModeString == "select")
    {
        return CONNECT_USE_IO_SELECT;
    }
    else if (connectUseIoModeString == "poll")
    {
        return CONNECT_USE_IO_POLL;
    }
    else if (connectUseIoModeString == "epoll")
    {
        return CONNECT_USE_IO_EPOLL;
    }
    return CONNECT_USE_IO_NONE;
}

int chooseLogLevel(std::string logLevelString)
{
    if (logLevelString == "debug")
    {
        return LOG_LEVEL_DEBUG;
    }
    else if (logLevelString == "info")
    {
        return LOG_LEVEL_INFO;
    }
    else if (logLevelString == "warn")
    {
        return LOG_LEVEL_WARN;
    }
    else if (logLevelString == "error")
    {
        return LOG_LEVEL_ERROR;
    }
    else if (logLevelString == "fatal")
    {
        return LOG_LEVEL_FATAL;
    }
}

// 设置文件描述符限制
void setFileDescriptorLimit()
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        logOutputInfoConsole("Current file descriptor limit: " + std::to_string(rl.rlim_cur) + "/" + std::to_string(rl.rlim_max));

        // 如果当前限制太低，尝试提高到合理值
        if (rl.rlim_cur < 65536)
        {
            rl.rlim_cur = std::min(static_cast<rlim_t>(65536), rl.rlim_max);
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0)
            {
                logOutputInfoConsole("Increased file descriptor limit to: " + std::to_string(rl.rlim_cur));
            }
            else
            {
                logOutputWarnConsole("Failed to increase file descriptor limit: " + std::string(strerror(errno)));
            }
        }
    }
    else
    {
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

        gConfigSocketIoUseMode = chooseConnectUseIoMode(config["config"]["socket"]["ioUseMode"].as<std::string>("none"));
        gConfigSocketNoBlockReadOrWrite = config["config"]["socket"]["noBlockReadOrWrite"].as<bool>(false);
        gConfigSocketNoBlockConnect = config["config"]["socket"]["noBlockConnect"].as<bool>(false);
        gConfigSocketAcceptTimeoutMs = config["config"]["socket"]["acceptTimeoutMs"].as<int>(5000);
        gConfigSocketConnectTimeoutMs = config["config"]["socket"]["connectTimeoutMs"].as<int>(-1);
        gConfigSocketPollingIntervalMs = config["config"]["socket"]["pollingIntervalMs"].as<int>(5000);
        gConfigSocketReadOrWriteTimeoutMs = config["config"]["socket"]["readOrWriteTimeoutMs"].as<int>(5000);

        gConfigTlsEnbale = config["config"]["tls"]["enable"].as<bool>(false);
        if (gConfigTlsEnbale)
        {
            gConfigTlsSocketIoUseMode = chooseConnectUseIoMode(config["config"]["tls"]["socketIoUseMode"].as<std::string>("none"));
            gConfigTlsSslIoUseMode = chooseConnectUseIoMode(config["config"]["tls"]["sslIoUseMode"].as<std::string>("none"));
            gConfigTlsUseThreadpoolSslConnect = config["config"]["tls"]["useThreadpoolSslAccept"].as<bool>(false);
            gConfigTlsNoBlockReadOrWrite = config["config"]["tls"]["noBlockReadOrWrite"].as<bool>(false);
            gConfigTlsNoBlockConnect = config["config"]["tls"]["noBlockConnect"].as<bool>(false);
            gConfigTlsAcceptTimeoutMs = config["config"]["tls"]["acceptTimeoutMs"].as<int>(5000);
            gConfigTlsConnectTimeoutMs = config["config"]["tls"]["connectTimeoutMs"].as<int>(-1);
            gConfigTlsPollingIntervalMs = config["config"]["tls"]["pollingIntervalMs"].as<int>(1000);
            gConfigTlsReadOrWriteTimeoutMs = config["config"]["tls"]["readOrWriteTimeoutMs"].as<int>(5000);
        }

        gConfigLogEnbale = config["config"]["log"]["enable"].as<bool>(true);
        if (gConfigLogEnbale)
        {
            gConfigLogEnbaleConsole = config["config"]["log"]["console"].as<bool>(true);
            gConfigLogLevel = chooseLogLevel(config["config"]["log"]["level"].as<std::string>("debug"));
            gConfigLogEnbaleFile = config["config"]["log"]["file"].as<bool>(false);
            if (gConfigLogEnbaleFile)
            {
                gConfigLogFilePathString = config["config"]["log"]["filePath"].as<std::string>("");
                if (gConfigLogFilePathString != "")
                {
                    std::filesystem::path checkLogPath(gConfigLogFilePathString);
                    if (std::filesystem::exists(checkLogPath) ||
                        std::filesystem::exists(checkLogPath.parent_path()))
                    {
                        gConfigLogFileChar = const_cast<char *>(gConfigLogFilePathString.c_str());
                        logOutputInfoConsole("log output file path: " + gConfigLogFilePathString);
                    }
                    else
                    {
                        gConfigLogEnbaleFile = false;
                        logOutputWarnConsole("log output file path error: " + gConfigLogFilePathString + " not exists or parent path not exists so will not output log file");
                    }
                }
                else
                {
                    logOutputWarnConsole("log file path is empty so log will not output to file");
                }
            }
        }

        gConfigThreadpoolMinWorkers = config["config"]["threadpool"]["minWokers"].as<int>(5);
        gConfigThreadpoolMaxWorkers = config["config"]["threadpool"]["maxWokers"].as<int>(10);
        gConfigThreadpoolClearThreadTimeMs = config["config"]["threadpool"]["clearThreadTimeMs"].as<int>(10000);
        gConfigThreadpoolPollingIntervalMs = config["config"]["threadpool"]["pollingIntervalMs"].as<int>(1000);
        gConfigThreadpoolStepAddWorkers = config["config"]["threadpool"]["stepAddThreadNumber"].as<int>(1);

        logOutputInfoConsole("load config success to filepath : " + configFile);

        gServerHostString = config["server"]["host"].as<std::string>("");
        gServerPort = config["server"]["port"].as<int>(0);
        if (gServerHostString == "")
        {
            logOutputFatalConsole("server host is empty");
            return EXIT_FAILURE;
        }
        else if (gServerPort <= 0)
        {
            logOutputFatalConsole("server port is empty");
            return EXIT_FAILURE;
        }
        else
        {
            logOutputInfoConsole("server host: " + gServerHostString + " port: " + std::to_string(gServerPort));
            gServerHostChar = const_cast<char *>(gServerHostString.c_str());
        }
        gServerSocketMaxBacklog = config["server"]["socket"]["maxBacklog"].as<int>(128);
        gServerSocketBufferSize = config["server"]["socket"]["bufferSize"].as<int>(8192);

        gServerTlsCertFileString = config["server"]["tls"]["cert"].as<std::string>("");
        if (gServerTlsCertFileString == "")
        {
            logOutputErrorConsole("server.tls.cert is empty");
        }
        else
        {
            std::filesystem::path checkCertPath(gServerTlsCertFileString);
            if (!std::filesystem::exists(checkCertPath))
            {
                logOutputErrorConsole("server.tls.cert file not exists");
                gServerTlsCertFileString = "";
            }
            else
            {
                gServerTlsCertFileChar = const_cast<char *>(gServerTlsCertFileString.c_str());
            }
        }
        gServerTlsKeyFileString = config["server"]["tls"]["key"].as<std::string>("");
        if (gServerTlsKeyFileString == "")
        {
            logOutputErrorConsole("server.tls.key is empty");
            std::filesystem::path checkKeyPath(gServerTlsKeyFileString);
            if (!std::filesystem::exists(checkKeyPath))
            {
                logOutputErrorConsole("server.tls.key file not exists");
                gServerTlsKeyFileString = "";
            }
            else
            {
                gServerTlsKeyFileChar = const_cast<char *>(gServerTlsKeyFileString.c_str());
            }
        }

        YAML::Node banList = config["server"]["connect"]["banIps"];
        YAML::Node allowList = config["server"]["connect"]["allowedIps"];

        for (const auto &item : banList)
        {
            if (item.IsScalar())
            { // 检查是否为标量值
                std::string value = item.as<std::string>("");
                if (value != "")
                {
                    gServerConnectBanIpsList.push_back(value);
                    logOutputDebugConsole("Firewall: Ban IP added - " + value);
                }
            }
        }

        for (const auto &item : allowList)
        {
            if (item.IsScalar())
            { // 检查是否为标量值
                std::string value = item.as<std::string>("");
                if (value != "")
                {
                    gServerConnectAllowIpsList.push_back(value);
                    logOutputDebugConsole("Firewall: Allow IP added - " + value);
                }
            }
        }

        // 记录防火墙配置摘要
        if (!gServerConnectBanIpsList.empty() || !gServerConnectAllowIpsList.empty())
        {
            logOutputInfoConsole("Firewall configured - Banned IPs: " + std::to_string(gServerConnectBanIpsList.size()) +
                                 ", Allowed IPs: " + std::to_string(gServerConnectAllowIpsList.size()));
        }
        else
        {
            logOutputWarnConsole("Firewall disabled - all IPs are allowed");
        }

        gClientHostString = config["client"]["host"].as<std::string>("");
        gClientPort = config["client"]["port"].as<int>(0);

        if (gClientHostString == "")
        {
            logOutputFatalConsole("client host is empty");
            return EXIT_FAILURE;
        }
        else if (gClientPort <= 0)
        {
            logOutputFatalConsole("client port is empty");
            return EXIT_FAILURE;
        }
        else
        {
            logOutputInfoConsole("client host: " + gClientHostString + " port: " + std::to_string(gClientPort));
            gClientHostChar = const_cast<char *>(gClientHostString.c_str());
        }

        gClientSocketBufferSize = config["client"]["socket"]["bufferSize"].as<int>(8192);

        gClientHostNameString = config["client"]["tls"]["hostname"].as<std::string>("");
        if (gClientHostNameString != "")
        {
            gClientHostNameString = const_cast<char *>(gClientHostNameString.c_str());
        }

        gClientSniString = config["client"]["tls"]["sni"].as<std::string>("");
        if (gClientSniString != "")
        {
            gClientSniString = const_cast<char *>(gClientSniString.c_str());
        }

        gServerCertFileString = config["server"]["tls"]["cert"].as<std::string>("");
        if (gServerCertFileString != "")
        {
            gServerCertFileString = const_cast<char *>(gServerCertFileString.c_str());
        }
    }
    catch (YAML::Exception &e)
    {
        std::string error = "Configuration error in config.yml: ";
        error.append(e.what());
        logOutputFatalConsole(error);
        return EXIT_FAILURE;
    }

    if (gConfigTlsEnbale)
    {
        if (gClientSocketBufferSize < 8192)
        {
            logOutputWarnConsole("Performance warning: In blocking TLS mode, clientSocketBufferSize (" + std::to_string(gClientSocketBufferSize) + ") is smaller than recommended minimum (8192). Consider increasing it.");
        }
        if (gServerSocketBufferSize < 8192)
        {
            logOutputWarnConsole("Performance warning: In blocking TLS mode, serverSocketBufferSize (" + std::to_string(gServerSocketBufferSize) + ") is smaller than recommended minimum (8192). Consider increasing it.");
        }
    }

    logOutputInfoConsole("ThreadPool configured - Min: " + std::to_string(gConfigThreadpoolMinWorkers) +
                         ", Max: " + std::to_string(gConfigThreadpoolMaxWorkers) +
                         ", Clear interval: " + std::to_string(gConfigThreadpoolClearThreadTimeMs) + "ms");

    rgThreadPool.setMinThreadNumber(gConfigThreadpoolMinWorkers);
    rgThreadPool.setMaxThreadNumber(gConfigThreadpoolMaxWorkers);
    rgThreadPool.setClearThreadTimeMs(gConfigThreadpoolClearThreadTimeMs);
    rgThreadPool.setWaitTimeMs(gConfigThreadpoolPollingIntervalMs);
    rgThreadPool.setStepAddThreadNumber(gConfigThreadpoolStepAddWorkers);
    rgThreadPool.openOutputError();

    if (gConfigTlsEnbale)
    {
        logOutputInfoConsole("Initializing TLS server mode...");
        initTlsServer();
        if (rgTlsSocketServerFd < 0)
        {
            logOutputErrorConsole("Failed to initialize TLS server socket");
            return EXIT_FAILURE;
        }
    }
    else
    {
        logOutputInfoConsole("Initializing plain socket server mode...");
        initSocketServer();
        if (rgSocketServerFd < 0)
        {
            logOutputErrorConsole("Failed to initialize server socket");
            return EXIT_FAILURE;
        }
    }

    rgThreadPool.init();

    if (gConfigTlsEnbale)
    {
        rgThreadPool.submitMission(tlsListenerCallback);
        logOutputInfoConsole("TLS server started successfully on " + gServerHostString + ":" + std::to_string(gServerPort));
    }
    else
    {
        rgThreadPool.submitMission(socketListenerCallback);
        logOutputInfoConsole("Plain socket server started successfully on " + gServerHostString + ":" + std::to_string(gClientPort));
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

    if (gConfigTlsEnbale)
    {
        closeTlsServer();
        rgThreadPool.waitMissionDone();
        rgThreadPool.shutdown();
        closeTlsResource();
    }
    else
    {
        closeSocketServer();
        rgThreadPool.waitMissionDone();
        rgThreadPool.shutdown();
    }

    if (rgLogFileOpen != NULL)
    {
        fclose(rgLogFileOpen);
        rgLogFileOpen = NULL;
    }

    return EXIT_SUCCESS;
}

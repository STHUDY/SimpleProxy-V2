#include "headfile.h"

bool SigintFlag = false;

void SigintHandler(int sig)
{
    SigintFlag = true;
    std::cout << " Ctrl+C pressed: wait close" << std::endl;
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
                logOutputInfoConsole("allow ip: " + value);
            }
        }
    }
    catch (YAML::Exception &e)
    {
        std::string error = "config.yml error: ";
        error.append(e.what());
        logOutputErrorConsole(error);
        return EXIT_FAILURE;
    }

    if (TlsNoBlock == false && TlsEnbale)
    {
        if (clientSocketBufferSize < 8192)
        {
            // logOutputWarnConsole("clientSocketBufferSize is too small,you shoud set more to 16384");
            logOutputWarnConsole("In blocking TLS mode (TlsNoBlock=false), clientSocketBufferSize (" + std::to_string(clientSocketBufferSize) + ") is smaller than the recommended minimum (8192). Consider increasing it for better performance.");
        }
        if (serverSocketBufferSize < 8192)
        {
            // logOutputWarnConsole("serverSocketBufferSize is too small,you shoud set more to 16384");
            logOutputWarnConsole("In blocking TLS mode (TlsNoBlock=false), serverSocketBufferSize (" + std::to_string(serverSocketBufferSize) + ") is smaller than the recommended minimum (8192). Consider increasing it for better performance.");
        }
    }

    logOutputInfoConsole("threadpool init : truly minThreadNumber: " + std::to_string(ThreadPoolMinThreadNumber) + " maxThreadNumber: " + std::to_string(ThreadPoolMaxThreadNumber));

    threadPool.setMinThreadNumber(ThreadPoolMinThreadNumber);
    threadPool.setMaxThreadNumber(ThreadPoolMaxThreadNumber);
    threadPool.setClearThreadTimeMs(ThreadPoolClearThreadTimeMs);
    threadPool.setWaitTimeMs(ThreadPoolWaitTimeMs);
    threadPool.setStepAddThreadNumber(ThreadPoolStepAddThreadNumber);

    if (TlsEnbale)
    {
        initTlsServer();
    }
    else
    {
        initSocketServer();
    }

    if (socketServerFd < 0)
    {
        logOutputErrorConsole("initSocketServer error");
        return EXIT_FAILURE;
    }

    threadPool.init();

    if (TlsEnbale)
    {
        threadPool.submitMission(tlsListenerCallback);
    }
    else
    {
        threadPool.submitMission(socketListenerCallback);
    }

    logOutputInfoConsole("server start at " + serverHost + ":" + std::to_string(serverPort));

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

//=================C库=====================
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/tls1.h>
#include <netdb.h>
#include <sys/epoll.h>
//=================C++库==================
#ifdef __cplusplus
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <queue>
#include <type_traits>
#include <utility>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <unordered_set>
#include <filesystem> 
#endif
//==================用户C库================
#include "nSocket.h"
#include "nTls.h"
#include "config.h"
#include "Log.h"
//================用户C++库=================
#ifdef __cplusplus
#include "ThreadpoolAutoCtrlByTime.hpp"
#include "config.hpp"
#include "Log.hpp"
#include "Callback.hpp"
#endif
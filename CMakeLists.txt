cmake_minimum_required(VERSION 3.10)

# 定义项目名称
project(SimpleProxy)

if(WIN32)
    # Windows 走 Winsock，没有 pthread；Threads 改成非 REQUIRED 在下面处理
else()
    find_package(Threads REQUIRED)
endif()
find_package(yaml-cpp REQUIRED)
find_package(OpenSSL REQUIRED)

# 生成 build/compile_commands.json，供 clangd / clang-tidy 使用（.clangd 的 CompilationDatabase 指向它）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 包含源文件
file(GLOB_RECURSE SOURCES
    "${PROJECT_SOURCE_DIR}/src/**/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/**/*.hpp"
    "${PROJECT_SOURCE_DIR}/src/**/*.h"
    "${PROJECT_SOURCE_DIR}/src/**/*.c")

# GLOB 在 Windows 上返回的是反斜杠路径，先统一成正斜杠，后面才好比较
set(SOURCES_NORMALIZED)
foreach(SRC IN LISTS SOURCES)
    file(TO_CMAKE_PATH "${SRC}" SRC_NORMALIZED)
    list(APPEND SOURCES_NORMALIZED "${SRC_NORMALIZED}")
endforeach()
set(SOURCES ${SOURCES_NORMALIZED})

# src/Platform 下两个平台各有一份实现，只编译当前平台的那份。
# 另一份如果也进编译，会因为缺 sys/epoll.h / SHUT_RDWR 或缺 winsock2.h 而报错。
if(WIN32)
    list(FILTER SOURCES EXCLUDE REGEX "/Platform/Linux/")
else()
    list(FILTER SOURCES EXCLUDE REGEX "/Platform/Windows/")
endif()

# 启用 C11 / C++17
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# ===== 构建类型选择：默认 Debug，可命令行覆盖 =====
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    Debug Release RelWithDebInfo MinSizeRel)

# 优化参数按编译器分开写：MSVC 不认 -O3 / -ftree-vectorize，
# 直接套用 gcc 参数只会得到 D9002 "忽略未知选项"，Release 等于没开优化。
if(MSVC)
    # /MD / MDd：必须显式指定动态 CRT。CMake 在 CMP0091 为 OLD 时不管理运行库，
    # cl.exe 自己默认是 /MT（静态），会和 vcpkg 的 x64-windows-static-md 库冲突
    # （triplet 名字里的 md 就是 dynamic CRT），报 LNK2038 RuntimeLibrary 不匹配。
    # 同时它连带决定 _ITERATOR_DEBUG_LEVEL，一起对不上。
    set(CMAKE_C_FLAGS_DEBUG   "/MDd /Od /Zi")
    set(CMAKE_C_FLAGS_RELEASE "/MD /O2 /Ob2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG   "/MDd /Od /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "/MD /O2 /Ob2 /DNDEBUG")
else()
    set(CMAKE_C_FLAGS_DEBUG   "-O0 -g")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -funroll-loops -ftree-vectorize -fvect-cost-model=unlimited")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -funroll-loops -ftree-vectorize -fvect-cost-model=unlimited")
endif()
# =================================================

# 动态包含 src 目录下的所有子目录（含 src/Platform/{Linux,Windows}）
file(GLOB_RECURSE SUBDIRS ${PROJECT_SOURCE_DIR}/src/*)

foreach(DIR IN LISTS SUBDIRS)
    get_filename_component(PATH ${DIR} DIRECTORY)
    # Windows 上 GLOB 结果是反斜杠，统一成正斜杠，和 .clangd 的 Add 列表保持一致
    file(TO_CMAKE_PATH "${PATH}" PATH)
    include_directories(${PATH})
endforeach()

if(WIN32)
    # 注意：add_compile_options / add_definitions 是目录级属性，只对其后创建的目标生效，
    # 所以必须放在 add_executable 之前，否则一个都不会生效。
    # /utf-8：源文件是 UTF-8 无 BOM，MSVC 默认按系统 ANSI 代码页（简体中文机器上是 GBK）读，
    # 中文注释的多字节序列会被误解从而吞掉换行，把 #endif / 声明搞成语法错误。
    add_compile_options(/utf-8)
    # WIN32_LEAN_AND_MEAN：不带 winsock.h，减少与 winsock2.h 的冲突
    # NOMINMAX：windows.h 会定义 min/max 宏，污染 C++ 的 std::min / std::max
    # _WIN32_WINNT=0x0601：WSAPoll 需要 Vista 以上
    # _CRT_SECURE_NO_WARNINGS：关掉 snprintf 之类的 "unsafe" 警告
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601)
endif()

# 声明可执行目标
add_executable(${CMAKE_PROJECT_NAME} src/main.cpp ${SOURCES})

if(WIN32)
    # ws2_32：Winsock
    # crypt32：Windows CryptoAPI。OpenSSL 在 Windows 上用它读系统证书库
    # （SSL_CTX_set_default_verify_paths 的默认实现走 CertOpenStore / CertFindCertificateInStore），
    # 不链的话 TLS 校验后端证书时会一堆 LNK2019。
    target_link_libraries(SimpleProxy PRIVATE ws2_32 crypt32)
else()
    target_link_libraries(SimpleProxy PRIVATE Threads::Threads)
endif()

if(TARGET yaml-cpp::yaml-cpp)
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp::yaml-cpp)
else()
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp)
endif()
target_link_libraries(SimpleProxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)

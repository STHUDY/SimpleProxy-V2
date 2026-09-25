cmake_minimum_required(VERSION 3.10)

# 定义项目名称
project(SimpleProxy)

find_package(Threads REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(OpenSSL REQUIRED)

# 包含源文件
file(GLOB_RECURSE SOURCES
    "${PROJECT_SOURCE_DIR}/src/**/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/**/*.hpp"
    "${PROJECT_SOURCE_DIR}/src/**/*.h"
    "${PROJECT_SOURCE_DIR}/src/**/*.c")

# 启用 C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# ===== 构建类型选择：默认 Debug，可命令行覆盖 =====
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    Debug Release RelWithDebInfo MinSizeRel)

set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -funroll-loops -ftree-vectorize -fvect-cost-model=unlimited")
# =================================================

# 动态包含 src 目录下的所有子目录
file(GLOB_RECURSE SUBDIRS ${PROJECT_SOURCE_DIR}/src/*)

foreach(DIR IN LISTS SUBDIRS)
    get_filename_component(PATH ${DIR} DIRECTORY)
    include_directories(${PATH})
endforeach()

# 声明可执行目标
add_executable(${CMAKE_PROJECT_NAME} src/main.cpp ${SOURCES})

target_link_libraries(SimpleProxy PRIVATE Threads::Threads)
if(TARGET yaml-cpp::yaml-cpp)
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp::yaml-cpp)
else()
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp)
endif()
target_link_libraries(SimpleProxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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

# 启用 C++11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# 动态包含 src 目录下的所有子目录
file(GLOB_RECURSE SUBDIRS ${PROJECT_SOURCE_DIR}/src/*)

foreach(DIR IN LISTS SUBDIRS)
    get_filename_component(PATH ${DIR} DIRECTORY)
    include_directories(${PATH})
endforeach()

# 声明可执行目标
add_executable(${CMAKE_PROJECT_NAME} src/main.cpp ${SOURCES})

target_link_libraries(SimpleProxy PRIVATE Threads::Threads)
target_link_libraries(SimpleProxy PRIVATE yaml-cpp)
target_link_libraries(SimpleProxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# 构建

## 依赖

| 依赖 | 用途 | 缺失后果 |
| --- | --- | --- |
| `yaml-cpp` | YAML 配置解析 | configure 失败 |
| `OpenSSL`（`SSL` + `Crypto`） | TLS | configure 失败 |
| pthreads | 仅 Linux | Linux 下 configure 失败 |

`CMakeLists.txt` 里前两个是 `find_package(... REQUIRED)`；`Threads` 改成**仅非 Windows** 才 `find_package(Threads REQUIRED)`，因为 Windows 走 `CRITICAL_SECTION` 且 vcpkg 环境下不一定提供 `Threads::Threads`。

C 方言固定 **C11**，C++ 固定 **C++17**：

```cmake
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
```

**默认构建类型是 Debug（`-O0 -g`）**，任何时延 / 吞吐结论都必须显式用 Release。

---

## Linux

```bash
sudo apt install build-essential cmake libyaml-cpp-dev libssl-dev

mkdir -p build && cd build
cmake ..                                   # Debug
make -j$(nproc)

# Release
cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
```

产物 `build/SimpleProxy`。

**未验证**：本文档编写时手头没有 gcc，Linux 构建与冒烟尚未实际执行。以上命令来自 AGENTS.md 的既有约定加本次改造的 CMake 改动。

---

## Windows（MSVC）

### 前置：vcpkg 依赖

`vcpkg.json` 声明了 `openssl` 和 `yaml-cpp`。装好的产物在 `vcpkg_installed/<triplet>/`，其中自带 CMake config（`share/openssl/OpenSSLConfig.cmake`、`share/yaml-cpp/yaml-cpp-config.cmake`），并有 release / debug 两套 `.lib`。

`VCPKG_ROOT` 为空时 CMake 找不到依赖，需要显式指前缀：

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  "-DCMAKE_PREFIX_PATH=$PWD\vcpkg_installed\x64-windows-static-md"

cmake --build build --config Release
```

Debug 把 `--config Release` 换成 `--config Debug`。产物 `build/Release/SimpleProxy.exe`。

### 用 vcpkg toolchain（替代方案）

vcpkg 本体存在时（`scripts/buildsystems/vcpkg.cmake`）：

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 -T vcpkg=x64-windows-static-md
cmake --build build --config Release
```

manifest 模式会校验 / 重装依赖，比指前缀慢，但依赖由 vcpkg 统一管理。

### VS 生成器的三个要点

1. **不要传 `-DCMAKE_BUILD_TYPE`。** VS 生成器是多配置的，构建类型在 build 阶段用 `--config` 选。传了会被记成 `CMAKE_BUILD_TYPE:UNINITIALIZED=Release`（`UNINITIALIZED` 就是"项目没认这个变量"）。
2. **不要用 `make`。** VS 生成器不产 Makefile，没有 make 可调。`$(nproc)` 也是 bash 语法。
3. PowerShell 里调用带引号的可执行文件路径要加调用运算符 `&`，否则后面的 `-D...` 会被解析成意外 token。

### MSVC 专有配置

```cmake
if(WIN32)
    add_compile_options(/utf-8)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX
                    -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601)
endif()
```

| 配置 | 原因 |
| --- | --- |
| `/utf-8` | 源文件是 UTF-8 **无 BOM**，MSVC 默认按系统 ANSI 代码页读（简体中文机器上是 GBK）。中文注释的多字节序列被误解后会错位、吞掉换行，把 `#endif` / 声明搞成语法错误 |
| `WIN32_LEAN_AND_MEAN` | 不带 `winsock.h`，减少与 `winsock2.h` 的冲突 |
| `NOMINMAX` | `windows.h` 会定义 `min` / `max` 宏，污染 `std::min` / `std::max` |
| `_WIN32_WINNT=0x0601` | `WSAPoll` 需要 Vista 以上 |
| `_CRT_SECURE_NO_WARNINGS` | 关掉 `snprintf` 之类的 "unsafe" 警告 |

**`add_compile_options` / `add_definitions` 必须写在 `add_executable()` 之前。** 这两个是目录级属性，只对其后创建的目标生效；写晚了目标已经建好，**一个都不会生效**。CMake 的报错方式是 C4819 满屏 + 中文注释里的声明变成"未声明的标识符"，排查起来很绕。

### CRT：必须显式 `/MD`

CMake 在 CMP0091 为 OLD 时不管理运行库，`cl.exe` 自己默认 `/MT`（静态），会和 vcpkg 的 `x64-windows-static-md` 冲突（triplet 名里的 `md` 就是 dynamic CRT）：

```
LNK2038: RuntimeLibrary 不匹配：MDd_DynamicDebug vs MT_StaticRelease
LNK2038: _ITERATOR_DEBUG_LEVEL 不匹配
```

所以优化参数按编译器分开写，并显式带上 `/MD` / `/MDd`：

```cmake
if(MSVC)
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
```

不按编译器分开写会怎样：MSVC 不认 `-O3` / `-ftree-vectorize`，只会给 `D9002 忽略未知选项`，**Release 等于没开优化**。

### 只编译当前平台的实现

`src/Platform/Linux/` 和 `src/Platform/Windows/` 各有一套同名功能的实现，GLOB 会把两份都收进来。另一份进编译就会因为缺 `sys/epoll.h` / `SHUT_RDWR` 或缺 `winsock2.h` 而报错：

```cmake
# GLOB 在 Windows 上返回反斜杠路径，先统一成正斜杠
set(SOURCES_NORMALIZED)
foreach(SRC IN LISTS SOURCES)
    file(TO_CMAKE_PATH "${SRC}" SRC_NORMALIZED)
    list(APPEND SOURCES_NORMALIZED "${SRC_NORMALIZED}")
endforeach()
set(SOURCES ${SOURCES_NORMALIZED})

if(WIN32)
    list(FILTER SOURCES EXCLUDE REGEX "/Platform/Linux/")
else()
    list(FILTER SOURCES EXCLUDE REGEX "/Platform/Windows/")
endif()
```

### 链接库

```cmake
if(WIN32)
    target_link_libraries(SimpleProxy PRIVATE ws2_32 crypt32)
else()
    target_link_libraries(SimpleProxy PRIVATE Threads::Threads)
endif()
target_link_libraries(SimpleProxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
```

- `ws2_32` —— Winsock
- `crypt32` —— Windows CryptoAPI。OpenSSL 在 Windows 上用它读系统证书库（`SSL_CTX_set_default_verify_paths` 的默认实现走 `CertOpenStore` / `CertFindCertificateInStore`），不链会一堆 `LNK2019`

`yaml-cpp` 优先用带命名空间的 target：

```cmake
if(TARGET yaml-cpp::yaml-cpp)
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp::yaml-cpp)
else()
    target_link_libraries(SimpleProxy PRIVATE yaml-cpp)
endif()
```

### 静态 OpenSSL 需要的额外系统库

如果绕过 CMake 直接调 `cl.exe` 链接 vcpkg 的静态 OpenSSL，还需要 `advapi32.lib`（`CryptAcquireContextW` 等）、`user32.lib`（`MessageBoxW`、`GetProcessWindowStation`）、`bcrypt.lib`、`gdi32.lib`。走 CMake + vcpkg config 时这些会由 `OpenSSLConfig.cmake` 处理。

---

## 编译数据库

`set(CMAKE_EXPORT_COMPILE_COMMANDS ON)` 生成 `build/compile_commands.json`，供 clangd / clang-tidy 使用（`.clangd` 的 `CompilationDatabase: build/` 指向它）。`build/` 在 `.gitignore` 里，需要重新 configure 才会生成。

---

## 常见构建期错误

| 现象 | 原因 |
| --- | --- |
| 满屏 `C4819` + 中文注释里的声明"未声明的标识符" | `/utf-8` 没生效（`add_compile_options` 写在了 `add_executable` 之后） |
| `LNK2038 RuntimeLibrary` 不匹配 | 没用 `/MD` |
| `LNK2001` 大量全局量找不到 | `config.h` 缺 `extern "C"`（MSVC 会 mangle 全局量） |
| `LNK2019 __imp_CertOpenStore` 之类 | 缺 `crypt32` |
| `C2956` "常用解除分配函数会被选为位置解除分配函数" | 用了 `new (std::align_val_t(64)) char[]`，MSVC 的过对齐数组 new 配对有问题。改用 `netAlignedAlloc` |
| `C2102 "=" 要求左值` | `netMutexLock(&m)` 传了 `&`，但宏内部已经带 `&`，展开成 `&(&m)`。去掉调用处的 `&` |
| `C2143 语法错误: 缺少 "{"` 在 `*` 前面 | 头里只前置声明了 `struct X;` 但签名里用了裸的 `X`。要用 `struct X *` |
| `epoll_*` / `SHUT_RDWR` 找不到 | 另一平台的 Platform 实现被编进来了，检查 `list(FILTER)` |
| `WSAE*` 找不到 | 用了 `strerror` 路径而不是 `netIs*()` 谓词 |
| 编译期只剩 4 个 `C4267`（`size_t`→`int`） | 已知遗留，不阻塞。`CallbackBase.cpp:58,64`、`SocketCallback.cpp:123`、`TlsCallback.cpp:410` |

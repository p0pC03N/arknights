---
title: "CreateProcess 挂起执行笔记"
description: "CreateProcess、CREATE_SUSPENDED 与进程启动流程笔记"
date: "2026-04-26"
category: "Windows / Process"
status: "Published"
draft: false
---
# `CreateProcess` 创建进程时的控制台与挂起执行

在 Windows 中，`CreateProcess` 不只是“运行一个程序”这么简单，它实际上参与了新进程的创建、主线程的建立以及初始执行状态的控制。对于逆向分析、进程注入、Hollowing 一类题目来说，这个 API 非常重要。

### 1. 获取目标程序的完整路径

在调用 `CreateProcess` 时，通常需要给出目标可执行文件的完整路径。为了方便实验，可以先用一个小程序获取当前工作目录，再拼出 `A.exe` 的路径。

```c
#include<stdio.h>
#include<direct.h>

int main()
{
    char path[100];
    getcwd(path,100);
    printf("%s\\A.exe",path);
    getchar();
    return 0;
}
```

这段代码的作用很直接：获取当前目录，并输出当前目录下 `A.exe` 的绝对路径，后续可以直接写入 `CreateProcess` 的参数中。

---

### 2. `CreateProcess` 的基本作用

下面是一段最基础的创建子进程代码：

```c
//环境：win10 VS2022
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <windows.h>

BOOL CreateChildProcess(PTCHAR ChildProcessName, PTCHAR CommandLine)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    // 创建子进程
    if (!CreateProcess(
        ChildProcessName,   // 可执行文件完整路径
        CommandLine,        // 命令行参数
        NULL,               // 进程安全属性
        NULL,               // 线程安全属性
        FALSE,              // 不继承句柄
        0,                  // 创建标志
        NULL,               // 使用父进程环境变量
        NULL,               // 使用父进程当前目录
        &si,                // STARTUPINFO 结构体
        &pi)                // PROCESS_INFORMATION 结构体
        )
    {
        printf("创建进程错误，错误代码：%d\n", GetLastError());
        return FALSE;
    }

    printf("进程句柄：%X\t进程ID：%X\n", pi.hProcess, pi.dwProcessId);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int main(int argc,char* argv[])
{
    TCHAR ApplicationName[] = TEXT("C:\\c test\\A.exe");
    TCHAR CmdLine[] = TEXT("1 https://www.baidu.com");
    CreateChildProcess(ApplicationName, NULL);

    getchar();
    return 0;
}
```

这段代码体现了几个核心点：

#### （1）`CreateProcess` 会返回两个很重要的对象信息

它通过 `PROCESS_INFORMATION` 返回：

* `hProcess`：新进程的句柄
* `hThread`：新进程主线程的句柄
* `dwProcessId`：进程 ID
* `dwThreadId`：主线程 ID

这说明创建进程时，不仅创建了进程本身，也创建了它的主线程。

#### （2）句柄需要手动关闭

`CreateProcess` 成功后，当前进程会持有目标进程和目标主线程的句柄。
这些句柄如果不再使用，就应该通过 `CloseHandle` 释放，否则会造成资源泄漏。

---

### 3. 默认情况下子进程未必会创建新控制台

如果父进程本身是控制台程序，那么默认通过 `CreateProcess` 创建出的子进程，通常也会使用当前控制台。因此，父进程和子进程的输出可能会显示在同一个控制台窗口中。

这一点要特别注意：

> 是否共用控制台，取决于创建标志和控制台相关属性，而不是“是不是不同进程”。

也就是说，**两个进程完全可以是独立的，但它们仍然可以共用同一个控制台窗口**。

如果想让子进程拥有独立控制台，就需要在 `dwCreationFlags` 中指定相应标志，例如：

```c
CREATE_NEW_CONSOLE
```

加入该标志后，子进程会创建自己的控制台窗口，和父进程的输出分离。

---

### 4. `CREATE_SUSPENDED` 的含义

在 `CreateProcess` 的创建标志中，一个非常关键的标志是：

```c
CREATE_SUSPENDED
```

它的作用是：

> 创建进程时，主线程先处于挂起状态，不立即执行。

这意味着系统会把进程对象和主线程对象都创建出来，但不会立刻调度该主线程运行，必须由调用者后续主动调用 `ResumeThread` 才能恢复执行。

---

### 5. 挂起创建时，进程的执行流程

普通创建和挂起创建的区别，关键就在于“线程是否立即运行”。

可以把挂起创建的大致流程理解为：

1. 映射目标 EXE 文件
2. 创建进程内核对象
3. 初始化进程的基本执行环境
4. 映射必要的系统模块，例如 `ntdll.dll`
5. 创建主线程内核对象
6. **如果指定了 `CREATE_SUSPENDED`，主线程此时不会立刻运行**
7. 调用 `ResumeThread` 后，线程恢复执行，后续初始化继续完成
8. 最终进入程序的正式执行阶段

这里最重要的理解是：

> 进程已经被创建出来了，但线程还没有真正开始跑用户代码。

所以“进程存在”和“线程开始执行”是两个不同层面的事情，不能混为一谈。

---

### 6. 挂起创建的代码实现

下面是使用 `CREATE_SUSPENDED` 的版本：

```c
//环境：win10 VS2022
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <windows.h>

BOOL CreateChildProcess(PTCHAR ChildProcessName, PTCHAR CommandLine)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    // 创建子进程
    if (!CreateProcess(
        ChildProcessName,   // 可执行文件完整路径
        CommandLine,        // 命令行参数
        NULL,               // 进程安全属性
        NULL,               // 线程安全属性
        FALSE,              // 不继承句柄
        CREATE_SUSPENDED,   // 以挂起方式创建
        NULL,               // 使用父进程环境变量
        NULL,               // 使用父进程当前目录
        &si,                // STARTUPINFO 结构体
        &pi)                // PROCESS_INFORMATION 结构体
        )
    {
        printf("创建进程错误，错误代码：%d\n", GetLastError());
        return FALSE;
    }

    printf("进程句柄：%X\t进程ID：%X\n", pi.hProcess, pi.dwProcessId);

    for (int i = 0; i < 10; i++)
    {
        Sleep(1000);
        printf("*************\n");
    }

    ResumeThread(pi.hThread);   // 恢复主线程执行

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int main(int argc,char* argv[])
{
    TCHAR ApplicationName[] = TEXT("C:\\c test\\A.exe");
    TCHAR CmdLine[] = TEXT("1 https://www.baidu.com");
    CreateChildProcess(ApplicationName, NULL);

    getchar();
    return 0;
}
```

---

### 7. 这段代码的关键知识点

这段代码的核心不在于延迟 10 秒，而在于演示：

#### （1）进程对象和线程对象已经创建完成

`CreateProcess` 返回成功后，目标进程已经存在，主线程句柄也已经拿到了。

#### （2）主线程暂时不执行

由于指定了 `CREATE_SUSPENDED`，所以子进程的主线程不会立刻运行。

#### （3）父进程可以在恢复前做额外操作

在 `ResumeThread` 之前，父进程拥有一个很有价值的时间窗口。
在这个阶段，可以对目标进程做很多事情，例如：

* 写入内存
* 修改入口点附近代码
* 设置断点
* 注入 DLL
* 做进程 Hollowing
* 进行参数或上下文篡改

#### （4）调用 `ResumeThread` 后子进程才真正开始往下执行

`ResumeThread(pi.hThread)` 的作用就是把挂起计数减一，当线程挂起计数归零后，线程恢复调度，开始执行。

---

### 8. 逆向应用

在普通开发中，挂起创建进程的需求不算常见；但在逆向、对抗和 CTF 场景中，它几乎是基础知识。

原因在于它给了攻击者或分析者一个“程序尚未真正执行”的切入点。这个切入点非常关键，因为很多保护逻辑、反调试逻辑、环境检测逻辑，都是在线程开始执行后才触发的。

因此，挂起创建的价值主要体现在下面几个方向：

#### 进程注入

先创建挂起进程，再把数据写入目标地址空间，最后恢复线程。

#### Process Hollowing / RunPE

先创建一个合法进程并挂起，再替换其映像内容，最后恢复执行。

#### 反调试对抗

在线程启动前提前布置断点、修改关键代码或控制上下文。

#### 分析初始化过程

通过挂起状态观察目标进程在真正开始执行前的内存、模块、线程状态。

---

### 9. 进程启动和线程执行
二者并不等价。

准确地说：

* **进程**是资源容器
* **线程**是执行载体
* **程序代码真正跑起来**依赖线程被调度执行

所以 `CREATE_SUSPENDED` 的本质并不是“进程没创建”，而是：

> 进程已经创建，主线程也已经创建，但主线程暂时处于挂起状态，尚未执行。

这句话对于理解 Windows 进程模型非常重要。

---




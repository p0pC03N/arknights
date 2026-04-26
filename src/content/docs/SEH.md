---
title: "TEB、TIB 与 SEH"
description: "Windows 线程环境块与结构化异常处理笔记"
date: "2026-04-26"
category: "Windows / Reverse"
status: "Published"
draft: false
---
# TEB、TIB 与 SEH

与 Linux 下常见的函数栈帧认知相比，Windows 的线程运行时环境要更“厚重”一些。
在很多逆向场景中，Windows 线程不仅仅依赖栈来保存 `saved ebp`、返回地址、局部变量、canary 等常见内容，还会借助一套额外的线程环境结构来维护线程私有状态。这套结构中，和逆向最密切相关的一部分，就是 **TEB、TIB 以及 SEH**。

---
## TEB 与 TIB 

要理解 SEH 存储在哪里，先要理解 **TEB** 和 **TIB**。

### 1. TEB

TEB，全称 **Thread Environment Block**，即**线程环境块**。
它是 Windows 为每一个线程分配的一块线程私有数据结构，用来保存这个线程在运行时需要频繁访问的信息。

每个线程都有自己独立的 TEB。
同一进程中的不同线程，TEB 不同；但它们通常会通过 TEB 中的字段指向同一个 PEB（进程环境块）。

TEB 中除了线程基础信息外，还包含大量与线程状态相关的字段，例如：

* 线程异常链信息
* 栈边界
* 线程局部存储（TLS）
* 线程 ID、进程 ID
* LastError
* 指向 PEB 的指针
* 各种子系统、运行库、GUI 相关字段

所以从逆向角度可以把 TEB 理解为：

> **每个线程独享的一份运行时状态总表**

---

### 2. TIB / NT_TIB

TIB，全称 **Thread Information Block**，常见类型名为 **NT_TIB**。
它并不是一个与 TEB 完全独立的平级对象，而是：

> **TEB 开头的一段基础结构**

也就是说，TEB 的最前面就是一个 `NT_TIB`。
在 WinDbg 中常能看到这样的定义：

```c
nt!_TEB
   +0x000 NtTib : _NT_TIB
```

这说明：

* TEB 从偏移 `0x000` 开始的部分，就是 `NT_TIB`

因此关系应该理解为：

* **TEB 包含 TIB**
* **TIB 是 TEB 的开头部分**

---

### NT_TIB 的核心结构

`NT_TIB` 的定义大致如下：

```c
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        ULONG Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;
```

其中最重要的几个字段如下。

#### ExceptionList

这是当前线程的 **SEH 链表头指针**。

它指向一个 `_EXCEPTION_REGISTRATION_RECORD` 结构，也就是当前线程异常处理链的第一个节点。
从这里开始，可以一路沿着 `Next` 指针遍历整个异常链。

这也是 x86 下分析 SEH 的核心入口。

---

#### StackBase

这是当前线程栈的一个边界。
由于 Windows 常见线程栈是**向低地址增长**的，所以 `StackBase` 通常表示栈的**高地址边界**。

---

#### StackLimit

这是当前线程栈的另一个边界，通常表示栈的**低地址边界**。

很多资料把 `StackBase` 和 `StackLimit` 叫作“栈底”和“栈顶”，但不同资料的命名习惯不统一，很容易把人绕晕。
从逆向角度，最稳妥的记法是：

* `StackBase`：高地址边界
* `StackLimit`：低地址边界

---

#### Self

`Self` 指向 `NT_TIB` 自己，因此通常也就等于当前线程 TEB 的起始地址。
这个字段在很多场景下都很有用，因为它能帮助程序快速取到当前线程的 TEB 指针。

---

### TEB 在 x86 中被访问

在 x86 用户态 Windows 中，`FS` 段寄存器被用来访问当前线程的 TEB。
因此，很多与线程环境相关的信息，都可以通过 `fs:[offset]` 的方式取到。

在这种模型下：

* `fs:[0x00]` 对应 `NT_TIB.ExceptionList`
* `fs:[0x04]` 对应 `NT_TIB.StackBase`
* `fs:[0x08]` 对应 `NT_TIB.StackLimit`
* `fs:[0x18]` 通常对应 `NT_TIB.Self`，也就是 TEB 地址

所以，在 x86 逆向里最经典的一条结论就是：

> **`fs:[0]` 就是当前线程的 SEH 链表头**

这也是为什么一看到 `mov eax, fs:[0]`，就应该立刻往异常链、SEH、线程环境块这条线上去想。

需要注意的是，更严谨的说法不是“TEB 存在 fs 段里”，而是：

> **通过 FS 段机制，可以访问当前线程的 TEB**

---
## SEH

SEH，Structured Exception Handling，即结构化异常处理。它是 Windows 平台上的异常处理模型，用来处理程序运行中出现的异常事件，例如除零、访问违例、非法指令、手工抛出的软件异常等。

在逆向里，不能把“异常”只理解成程序出错。异常本质上是一次控制流切换机会。当 CPU 或操作系统发现程序当前无法按原路径继续执行时，Windows 不会立刻简单粗暴地把进程杀掉，而是会去找“有没有人愿意处理这次异常”。这个“愿意处理的人”，就是异常处理函数，也就是 SEH 链上的 handler。

所以，SEH 的核心不是“报错弹窗”，而是：

* 程序运行时维护了一条异常处理链；
* 异常发生时，系统沿着这条链查找处理者；
* 找到能处理的 handler 后，流程会被导向对应逻辑；
* 找不到时，才会走到默认的未处理异常流程。
* 这就是逆向时必须建立的第一层认知：SEH 是一套异常到控制流的分发机制。


### SEH 链表的结构
在 x86 Windows 下，SEH 链是按线程维护的。它不属于整个进程的统一全局结构，而是每个线程自己有自己的一条链。线程切换并不会把别的线程的 SEH 拿过来共用。

异常处理链的表头可以从线程环境块中取到。经典的 x86 里常见的是：
```asm
mov eax, fs:[0]
```
这里的 fs:[0] 指向当前线程 SEH 链的第一个节点。原文中提到，线程初始化时，系统会自动在栈中安装一个默认的 SEH 结构，链尾通常以 0xFFFFFFFF 作为结束标记。

SEH 链上的基础节点结构通常写作：

```c
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;
```

它是一个典型的单链表节点，包含两个关键字段：

* `Next`：指向下一个异常注册记录
* `Handler`：当前节点对应的异常处理函数

因此，SEH 的本质之一，就是：

> **当前线程维护着一条异常处理链，链上每个节点都提供一个 handler**

当异常发生时，系统就会从链头开始，沿链表逐个尝试这些 handler。

---

### 函数栈帧里出现的 SEH 记录

在 x86 下，当一个函数使用 `__try/__except` 或 `__try/__finally` 时，编译器通常会在该函数的栈帧中构造一个异常注册记录，并将它挂接到当前线程的 SEH 链表头上。

这个过程的逻辑可以抽象为：

```c
record.Next = fs:[0];
record.Handler = handler;
fs:[0] = &record;
```

如果翻译成更熟悉的汇编形态，常常会看到类似这样的代码：

```asm
push handler
push fs:[0]
mov  fs:[0], esp
```

这几条指令的含义就是：

1. 把原来的异常链头压栈，作为 `Next`
2. 把当前函数的 handler 压栈
3. 用当前栈顶地址更新 `fs:[0]`

这样一来，当前函数就在异常链表头部插入了一个新节点。

当函数退出时，编译器还会把链恢复回去，典型逻辑相当于：

```c
fs:[0] = record.Next;
```

因此，逆向中如果在函数入口看到这类指令，就说明：

* 这个函数正在挂接一个新的 SEH 节点
* 当前函数大概率使用了异常处理机制

---

### SEH 工作流程

当程序发生异常时，系统大致会执行如下流程：

1. CPU 发现异常，例如除 0、访问违规、非法指令等
2. 内核和异常分发机制将异常传递到用户态
3. Windows 获取当前线程的 TEB
4. 从 `TEB->NtTib.ExceptionList` 开始遍历 SEH 链
5. 依次调用链上各节点的 handler
6. 某个 handler 决定：

   * 处理该异常
   * 继续向后搜索
   * 执行栈展开等后续动作
7. 如果没有任何 handler 处理该异常，就进入未处理异常流程，最终可能导致程序崩溃

因此，SEH 并不是“异常一发生就直接跳到某个固定函数”，而是：

> **系统从当前线程的异常链头出发，一层层向后询问谁来处理异常**

这也是为什么异常处理经常会改变控制流。
一个异常点并不一定意味着程序马上崩溃，它也可能只是进入了某个隐藏的 handler，然后继续执行新的逻辑。

---

## TEB 与 PEB

TEB 是线程级结构，PEB 是进程级结构。

一个进程中可能有很多线程，因此：

* 每个线程都有自己的 TEB
* 同一进程中的多个线程会各自拥有不同的 TEB
* 这些 TEB 往往会通过 `ProcessEnvironmentBlock` 字段指向同一个 PEB

因此，在很多无导入解析、模块遍历、反调试场景中，分析路径常常是：

```text
TEB → PEB → Loader Data → 模块链表
```

所以，TEB 不仅与 SEH 相关，也是通向 PEB 和更大范围进程信息的重要跳板。

---

### TEB、TIB 和 SEH

从逆向视角，可以用下面这段话来概括三者关系：

> **TEB 是每个线程独有的运行时信息块；TIB（NT_TIB）是 TEB 开头的一段基础结构；而 x86 下的 SEH 链表头就保存在 `NT_TIB.ExceptionList` 中。**
> 因此，在 32 位 Windows 用户态程序里，`fs:[0]` 本质上就是当前线程的异常链表头。
> 编译器在进入 `__try/__except` 或 `__try/__finally` 保护区时，通常会在函数栈帧中构造一个异常注册记录，把它挂到该链表头上；在函数退出时再恢复原有链表。
> 所以，x86 的 SEH 可以理解为：**TEB 保存链头，栈帧保存节点，系统在异常发生时沿链表逐个分发 handler。**

---

## 逆向

当分析 Windows x86 程序时：

* 看到 `mov eax, fs:[0]`，首先想到 **SEH 链头**
* 看到 `mov eax, fs:[18h]`，首先想到 **TEB 指针**
* 看到 `push fs:[0] / mov fs:[0], esp`，首先想到 **正在挂新的异常注册记录**
* 看到函数末尾恢复 `fs:[0]`，首先想到 **正在摘除当前函数的 SEH 节点**
* 看到异常、除 0、访问违规、`int 3`、`RaiseException` 等线索，首先判断：

  * 是不是在借异常隐藏控制流
  * 是不是在利用 handler 进行跳转
  * 是不是在做反调试或混淆

---

## 结语

TEB、TIB 与 SEH 并不是零散的几个概念，而是一套彼此紧密关联的线程运行时基础设施。

* **TEB** 是线程私有的总环境块
* **TIB / NT_TIB** 是 TEB 开头的一段基础信息区
* **SEH 链头** 保存在 `NT_TIB.ExceptionList`
* **SEH 节点** 通常由函数栈帧承载
* **异常发生时**，系统从当前线程 TEB 中取出异常链头，沿链逐个分发 handler

对于逆向分析而言，理解这些内容之后，很多原本看起来“莫名其妙”的 `fs:[0]`、异常跳转、栈上神秘结构、控制流绕行，都会变得清晰起来。

真正重要的不是死记结构体，而是建立一种稳定的分析意识：

> **看到线程环境访问，就想到 TEB；看到 `fs:[0]`，就想到 x86 SEH；看到异常，就想到它可能不仅是错误，更可能是控制流的一部分。**

---


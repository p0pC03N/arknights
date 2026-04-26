---
title: "驱动通信与 IOCTL"
description: "DeviceIoControl、IOCTL 编码与驱动层通信笔记"
date: "2026-04-26"
category: "Windows / Driver"
status: "Published"
draft: false
---
# 驱动通信
## DeviceIoControl
```c
BOOL DeviceIoControl(
    HANDLE hDevice,              // 设备句柄
    DWORD dwIoControlCode,       // 控制码
    LPVOID lpInBuffer,           // 输入数据缓冲区指针
    DWORD nInBufferSize,         // 输入数据缓冲区长度
    LPVOID lpOutBuffer,          // 输出数据缓冲区指针
    DWORD nOutBufferSize,        // 输出数据缓冲区长度
    LPDWORD lpBytesReturned,     // 输出数据实际长度单元长度
    LPOVERLAPPED lpOverlapped    // 重叠操作结构指针
);
```
DeviceIoControl 的定义就是：它会把一个控制码直接发送给指定设备驱动，从而让设备执行相应操作。

+ 设备句柄用来标识你所訪问的设备。 
+ 发送不同的控制码，能够调用设备驱动程序的不同类型的功能。在头文件winioctl.h中，提前定义的标准设备控制码，都以IOCTL或FSCTL开头。比如，IOCTL_DISK_GET_DRIVE_GEOMETRY是对物理驱动器取结构參数（介质类型、柱面数、每柱面磁道数、每磁道扇区数等）的控制码，FSCTL_LOCK_VOLUME是对逻辑驱动器的卷加锁的控制码。 
  > 驱动并不是只会“读”和“写”。除了 ReadFile、WriteFile 这种常规 I/O 以外，很多设备和文件系统还需要支持一大堆“特殊操作”。这些特殊操作不能靠普通读写表达，于是 Windows 定义了一套“控制请求”机制。这个“控制请求”的核心就是控制码。看到这个编号，就执行对应的功能。
+ 输入输出数据缓冲区是否须要，是何种结构，以及占多少字节空间，全然由不同设备的不同操作类型决定。在头文件winioctl.h中，已经为标准设备提前定义了一些输入输出数据结构。重叠操作结构指针设置为NULL，DeviceIoControl将进行堵塞调用；否则，应在编程时按异步操作设计。 
  > lpInBuffer 和 lpOutBuffer 里到底塞什么，全由控制码决定。
  > 很多控制命令不是简单的整数参数，而是要传一组语义化字段。微软的 winioctl.h 头文件里定义了大量标准控制码对应的结构体，例如各种磁盘、分区、卷、存储、USN、重解析点相关结构。微软的 winioctl.h 参考页本身就是这些结构和控制码的索引入口。
  > I/O 控制码的缓冲方式分为 METHOD_BUFFERED、METHOD_IN_DIRECT、METHOD_OUT_DIRECT、METHOD_NEITHER 四种。
    + METHOD_BUFFERED
  
      I/O 管理器分配一个系统缓冲区，驱动主要通过 Irp->AssociatedIrp.SystemBuffer 访问数据。这个缓冲区既表示输入，也表示输出。
    + METHOD_IN_DIRECT / METHOD_OUT_DIRECT
  
      IRP 里除了系统缓冲区，还会通过 Irp->MdlAddress 描述第二个用户缓冲区。这些 direct 方法会提供 MDL
    + METHOD_NEITHER

      I/O 管理器既不提供系统缓冲区，也不提供 MDL，而是把用户模式虚拟地址直接交给驱动。此时系统不会替驱动验证或映射这些地址。
  > 如果句柄是以非重叠方式打开，lpOverlapped 会被忽略，这种情况下函数在操作完成或出错前不会返回。

  如果句柄是以 FILE_FLAG_OVERLAPPED 打开的，并且进行了 overlapped I/O，那么 DeviceIoControl 会立即返回，完成后再通过事件、GetOverlappedResult 或完成端口获取结果。
    + 如果 lpOverlapped 为 NULL，那么 lpBytesReturned 不能 为 NULL
    
    + 即使这个操作没有输出数据，DeviceIoControl 仍然会用到 lpBytesReturned
    
    + N如果 lpOverlapped 不为 NULL，那么 lpBytesReturned 可以 为 NULL
    
    + 在 overlapped 模式下，如果它不为 NULL，在操作完成前它的值也没有意义；应该通过 GetOverlappedResult 或完成端口拿实际字节数。
      >  OVERLAPPED 是一个结构体。是异步 I/O 的状态记录单,这个结构在使用前应初始化为 0,一次异步请求要用一个独立的 OVERLAPPED。它允许你把 I/O 时间 和 CPU 干别的事的时间 叠在一起，所以叫重叠。
## IOCTL
IOCTL 是 I/O Control Code,驱动提供给外部调用者的一种“控制命令编号”。应用程序与驱动程序之间，常通过 I/O 控制请求进行交互。用户态程序通常调用 DeviceIoControl，把一个自定义或系统定义的 IOCTL 发送给设备句柄。I/O 管理器据此构造一个 IRP_MJ_DEVICE_CONTROL 请求，并把控制码放在当前 I/O 栈位置的 Parameters.DeviceIoControl.IoControlCode 字段中，然后把该 IRP 发送给对应驱动的 IRP_MJ_DEVICE_CONTROL 派遣函数。驱动在派遣函数中读取 IOCTL，检查输入输出缓冲区和长度，再根据控制码分支执行相应逻辑。

也就是说用户层并不能像调用 DLL 导出函数那样直接调用内核驱动。用户层和驱动之间之所以能通信，是因为 Windows I/O 管理器提供了一套标准机制：

  1. 驱动创建设备对象并暴露一个可打开的名字
  2. 用户层通过 CreateFile 打开这个名字
  3. 用户层调用 DeviceIoControl
  4. I/O 管理器构造一个 IRP_MJ_DEVICE_CONTROL
  5. 驱动在对应派遣函数中取出控制码、输入输出缓冲区并处理
  
一个典型流程包括：
```
驱动用 CTL_CODE 定义 IOCTL；
创建设备对象并暴露可打开的名字；
注册 IRP_MJ_CREATE、IRP_MJ_CLOSE、IRP_MJ_DEVICE_CONTROL 等分发例程；
在 IRP_MJ_DEVICE_CONTROL 中处理各个自定义 IOCTL；
用户态通过 CreateFile 打开设备名
再通过 DeviceIoControl 发送控制码和输入输出缓冲区
最后关闭句柄
```
### 定义IOCTL
IOCTL 是一个32位的数字。
```c
#define IOCTL_MY_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
这个宏本质上是在打包四类信息：

  + `DeviceType`：设备类型
  + `Function`：功能号
  + `Method`：数据传输方式
  + `Access`：访问权限要求

  这个命令属于哪类设备、它表示什么功能、数据怎么传、什么权限的调用者能发。
#### 32 位布局
```
[ Common | Device Type | Access | Custom | Function | Method ]
   31       16..30      14..15    13       2..12      0..1
```
1. bit 0-1：`Method`

最低两位表示数据传输方式，也就是：

* `METHOD_BUFFERED`
* `METHOD_IN_DIRECT`
* `METHOD_OUT_DIRECT`
* `METHOD_NEITHER`

这两位不决定“功能做什么”，而决定：

> **输入输出缓冲区最终如何从用户层传到驱动层**

---

2. bit 2-12：`Function`

这 11 位表示**功能号**。

这才是真正区分“这个 IOCTL 到底是查询版本、还是设置配置、还是触发某个动作”的编号。

很多驱动会把自定义功能号写成：

* `0x800`
* `0x801`
* `0x802`
* `0x803`

这是因为自定义功能号通常从这个范围起用。

---

3. bit 13：`Custom`

这个位表示：
**这是不是一个厂商自定义 IOCTL。**

很多初学资料会把这个位和最高位混掉，这是很常见的错误。
需要注意的是，和“自定义”有关的位其实有两个：

* bit 13：`Custom`
* bit 31：`Common`

它们都和“用户/厂商自定义”有关，但作用并不一样

---

4. bit 14-15：`Access`

这两位表示访问要求。

这不是“设备打开失败时该怎么办”，而是：

> **调用者打开设备句柄时，请求了什么访问权限，I/O 管理器才允许它发送这个 IOCTL。**

例如：

* `FILE_ANY_ACCESS`
* `FILE_READ_DATA`
* `FILE_WRITE_DATA`
* `FILE_READ_DATA | FILE_WRITE_DATA`

这意味着 IOCTL 本身就携带了一部分权限约束。

所以一个真正敏感的 IOCTL，不应该随便定义成 `FILE_ANY_ACCESS`，否则任何拿到句柄的调用者都可能触发它。

---

5. bit 16-30：`DeviceType`

这部分表示这个 IOCTL 所属的设备类型。

它并不是随便写个常量就行，而是应该和设备对象本身的 `DeviceType` 一致。
也就是说：

> 设备对象是什么类型
> 它对应的 IOCTL 也应当属于这个类型

这可以看作是一种一致性约束。

---

6. bit 31：`Common`

最高位是 `Common` 位。

很多旧资料或者非官方讲解容易把它说成“最高位定义为定制位”，这种说法不够精确。
更准确的理解是：

> **当你使用厂商自定义的设备类型时，需要置这个位**

所以：

* `bit 31` 更偏向于“设备类型那半边的厂商自定义标记”
* `bit 13` 更偏向于“功能号那半边的厂商自定义标记”

这两个位一起，组成了 IOCTL 的“自定义扩展区”概念。

---
#### 4种method
* `METHOD_BUFFERED`
* `METHOD_IN_DIRECT`
* `METHOD_OUT_DIRECT`
* `METHOD_NEITHER`
  
1. `METHOD_BUFFERED`
可以把它理解成：

> 系统在中间给你准备了一个“中转缓冲区”

用户层传进来的输入数据先被拷进去，驱动处理完后，再把输出结果从这个系统缓冲区拷回用户层。

所以它的特点是：

* 简单
* 安全性相对高
* 适合小数据量
* 多一次拷贝

这也是很多入门驱动最爱用的方式。

---

2. `METHOD_IN_DIRECT`

这是 Direct I/O 的一种。

可以先粗略理解为：

> 用户层有一块较大的输入数据，系统不想简单粗暴地复制，而是用更偏底层的方式把这块内存交给驱动访问

它通常会涉及 MDL 之类的机制。
它比 buffered 更接近底层，也更适合较大数据传输。

---

3. `METHOD_OUT_DIRECT`

同样属于 Direct I/O。

可以先粗略理解为：

> 驱动需要往用户层的一块较大缓冲区里写结果

和 `METHOD_IN_DIRECT` 一样，它强调的是更底层、更高效的数据通道，而不是“中转复制”。

---

4. `METHOD_NEITHER`

这是最危险也最容易出问题的一种。

它的意思基本可以理解成：

> I/O 管理器不帮你准备系统缓冲区，也不帮你做完整的映射，驱动自己去处理用户态给来的地址

这种方式极其灵活，但也极其危险。

---
### 驱动创建设备对象并暴露名字

驱动加载后会创建一个设备对象，并给它建立一个用户层可访问的名字。

这样用户层才能通过 `CreateFile` 去打开它。

这一步的本质是：

> 给用户态提供一个“通信入口”

---

### 驱动注册 `IRP_MJ_DEVICE_CONTROL` 处理函数

驱动对象有一个分发表，里面保存各种 MajorFunction 对应的派遣函数。

其中和 IOCTL 通信最关键的是：

* `IRP_MJ_CREATE`
* `IRP_MJ_CLOSE`
* `IRP_MJ_DEVICE_CONTROL`

用户层 `CreateFile` 时，驱动会收到 `IRP_MJ_CREATE`；
用户层 `CloseHandle` 时，驱动会收到 `IRP_MJ_CLOSE`；
用户层 `DeviceIoControl` 时，驱动会收到 `IRP_MJ_DEVICE_CONTROL`。

---

### 用户层 `CreateFile` 打开设备

用户层通过类似下面的方式打开驱动提供的名字：

```c
HANDLE h = CreateFile(L"\\\\.\\MyDevice", ...);
```

拿到句柄后，这个句柄就成了后续发送 IOCTL 的“目标对象”。

---

### 用户层准备输入输出缓冲区，调用 `DeviceIoControl`

用户层会准备好：

* 输入结构体
* 输出结构体
* 它们各自的长度
* 要发送的 IOCTL

然后调用：

```c
DeviceIoControl(h, code, inBuf, inLen, outBuf, outLen, &ret, NULL);
```

这一步是用户层看见的全部。

---

### I/O 管理器构造 `IRP_MJ_DEVICE_CONTROL`

用户层调用 `DeviceIoControl` 后，I/O 管理器会构造一个 IRP。

这里必须特别纠正一个常见错误：

> **自定义控制码不是放在 `MinorFunction` 里判断的。**

正确做法是：

* `MajorFunction = IRP_MJ_DEVICE_CONTROL`
* 具体的控制码在当前栈位置里的 `IoControlCode`

也就是说，驱动真正应该分支判断的是：

> `IoControlCode`

而不是所谓“MinorFunction 是自定义控制码”。

---

### 驱动在派遣函数中根据 IOCTL 分支处理

驱动的 `IRP_MJ_DEVICE_CONTROL` 派遣函数里，典型流程大概是：

1. 取当前栈位置
2. 读 `IoControlCode`
3. 读输入长度和输出长度
4. 根据 Method 决定从哪里取数据
5. 校验缓冲区和长度
6. 根据控制码进入不同分支
7. 处理请求
8. 设置返回状态和返回字节数
9. 完成 IRP

所以驱动中最典型的写法往往像一个大 `switch`：

```c
switch (IoControlCode) {
case IOCTL_A:
    ...
    break;
case IOCTL_B:
    ...
    break;
}
```

这一层你应该把它理解成：

> **驱动的命令分发表**

---

### 驱动返回结果，用户层收结果并关闭句柄

处理完后，驱动会把结果写回输出缓冲区，并返回：

* 成功/失败状态
* 实际返回字节数

用户层的 `DeviceIoControl` 返回后，就可以从输出缓冲区里取结果。
最后 `CloseHandle` 关闭设备句柄。

---
## FSCTL 
FSCTL 是 File System Control Code。

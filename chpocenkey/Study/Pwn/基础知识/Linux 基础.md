## 常用命令
若命令行的第一个单词不是一个内置的 shell 命令，shell 就会假设这是一个可执行文件的名字，它将加载并运行这个文件
bash 是当前 Linux 标准的默认 shell，也可以选用其他的 shell 脚本语言
```
标准格式：命令名称 [命令参数] [命令对象]
命令参数有长和短两种格式，分别用 "--" 和 "-" 做前缀

ls [OPTION]... [FILE]  列出文件信息

```
## 流、管道和重定向
**流（stream）** 可以理解为一串连续的、可边读边处理的数据。其中 **标准流（standard streams）** 可以分为标准输入、标准输出和标准错误

**文件描述符（file descriptor）** 是内核为管理已打开文件所创建的 **索引** ，使用一个非负整数来指代被打开的文件

	Linux 中一切皆可看作文件，流也可以被看做文件，所以输入和输出都被当作对应文件的读和写来执行

**标准流** 定义在 **头文件 `unistd.h`** 中

| 文件描述符 | 常量            | 用途   | stdio 流 |
| ----- | ------------- | ---- | ------- |
| 0     | STDIN_FILENO  | 标准输入 | stdin   |
| 1     | STDPUT_FILENO | 标准输出 | stdout  |
| 2     | STDERR_FILENO | 标准错误 | stderr  |

**管道（pipeline）** 是指一系列进程通过标准流连接在一起，前一个进程的输出直接作为后一个进程的输入。管道符号为 `|`

输入输出重定向

| 重定向符号                 | 作用                                         |
| --------------------- | ------------------------------------------ |
| `cmd > file`          | 将 `cmd` 的标准输出重定向并覆盖 `file`                 |
| `cmd >> file`         | 将 `cmd` 的标准输出重定向并追加到 `file`                |
| `cmd < file`          | 将 `file` 作为 `cmd` 的标准输入                    |
| `cmd << tag`          | 从标准输入中读取，直到遇到 `tag` 为止                     |
| `cmd < file1 > file2` | 将 `file1` 作为 `cmd` 的标准输入并将标准输出重定向到 `file2` |
| `cmd 2 > file`        | 将 `cmd` 的标准错误重定向并覆盖 `file`                 |
| `cmd 2 >> file`       | 将 `cmd` 的标准错误重定向并追缴到 `file`                |
| `2 >& 1`              | 将标准错误和标准输出合并                               |
## 根目录结构
Linux 中一切都可以看成文件，所有的文件和目录被组织成一个以根节点 `/` 开始的树状结构，系统中的每个文件都是根目录的直接或简介后代

Linux 文件有三种基本文件类型
- **普通文件：** 包含文本文件（只含有 ASCII 或 Unicode 字符）和二进制文件（所有其他文件）
- **目录：** 包含一组连接的文件，其中每个连接都将一个文件名映射到一个文件，这个文件可能是另一个目录
- **特殊文件：** 包括快文件、符号链接、管道、套接字等
## 用户组及文件权限
Linux 支持多用户，每个用户都有 User ID(UID) 和 Group ID(GID) 
UID 是对一个用户的单一身份标识，UID 为 0 的 root 用户类似于系统管理员，它具有系统的完全访问权
GID 对应多个 UID，GID 的关系存储在 `/etc/group` 文件中

所有用户的信息（除了密码）都保存在 `/etc/passwd` 文件中，加密过的用户密码保存在 `/etc/shadow` 文件（仅 root 权限可以访问）中

shell 中普通用户以 `$` 开头，root 用户以 `#` 开头

在 Linux 中，文件或目录权限的控制分别以读取、写入和执行三种一般权限来区分，另有三种特殊权限可供运用
## 环境变量
环境变量为系统或应用程序设置了一些参数
环境变量字符串以 `name=value` 的形式存在，大多数的 `name` 由大写字母加下画线组成，通常将 `name` 部分称为 **环境变量名*；`value` 部分称为 **环境变量的值**，需要以 `/0`结尾
### Linux 环境变量的分类
**按照生命周期划分**
- **永久环境变量：** 修改相关配置文件，永久生效
- **临时环境变量：** 通过 `export` 命令在当前终端下声明，关闭终端后失效
**按照作用域划分**
- **系统环境变量：** 对该系统中所有用户生效，可以在 `/etc/profile` 文件中声明
- **用户环境变量：** 对特定用户生效，可以在 `~/.bashrc` 文件中声明
### 命令
`env` 命令可以打印所有的环境变量，也可以对环境变量进行设置
```
env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
```
### 常见的环境变量
##### LD_PRELOAD
`LD_PRELOAD` 环境变量可以定义程序运行时 **优先加载的动态链接库**

	由于可以通过定义该变量覆盖掉后加载的库中的函数和符号，所以在 CTF 中可以通过加载一个特定的 libc 以实现特定的目的
##### environ
全局变量 `environ` 定义在 `libc` 中，它指向 **内存** 中位于 **栈** 上的 **环境变量表**

	泄露 environ 指针的地址即可获得栈地址
## procfs 文件系统
`procfs` 文件系统是 Linux 内核提供的 **虚拟文件系统**，只占用内存而不占用存储，为 **访问内核数据** 提供接口。可以通过 `procfs` 查看有关系统硬件及当前正在运行进程的信息，可以通过修改其中的某些内容改变内核的运行状态
每个正在运行的进程都对应 `/proc` 下的一个目录，目录名是该进程的 PID
## 字节序
计算机中采用两种 **字节存储机制：**
- **大端（Big-endian）：** MSB（Most Significan Bit/Byte）在 **存储** 时放在 **低地址**，**传输** 时放在 **流的开始**；LSB（Least Significan Bit/Byte）在 **存储** 时放在 **高地址**，**传输** 时放在 **流的末尾**
- **小端（Little-endian）：** MSB（Most Significan Bit/Byte）在 **存储** 时放在 **高地址**，**传输** 时放在 **流的末尾**；LSB（Least Significan Bit/Byte）在 **存储** 时放在 **低地址**，**传输** 时放在 **流的开始**
常见的 **Intel 处理器** 使用 **小端**，而 **PowerPC系列处理器**、**TCP/IP协议** 和 **Java 虚拟机** 使用 **大端**

**示例**
字符串 `12345678`

| 地址    | 大端   | 小端   |
| ----- | ---- | ---- |
| 1000H | 0x12 | 0x78 |
| 1001H | 0x34 | 0x56 |
| 1002H | 0x56 | 0x34 |
| 1003H | 0x78 | 0x12 |
## 调用约定
函数调用约定是对函数调用时如何传递参数的一种约定
### 从内核接口看
#### x86-32 系统调用约定
- Linux 系统调用使用 **寄存器** 传递参数
- `eax` 是 `syscall_number`（系统调用号），`ebx`、`ecx`、`edx`、`esi` 和 `ebp` 用于将 6 个参数传递给系统调用
- - 返回值保存在 `eax` 中，所有其他寄存器保留在 `int 0x80` 中
#### x86-64 系统调用约定
- 内核接口使用的寄存器有 `rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9`
- 系统调用通过 `syscall` 指令完成
- 除了 `rcx`、`r11`、`rax`，其他寄存器都被保留
- `rax` 保存 `syscall_number` （系统调用号）
- 系统调用的参数限制为 6 个，不直接从堆栈上传递任何参数
- 返回时，`rax` 中包含系统调用的结果，而且只用 `INTEGER` 或 `MEMORY` 类型的值才会被传递给内核
### 从用户接口看
#### x86-32 函数调用约定
- 参数通过栈进行传递
- 最后一个参数第一个被放入栈中，直到所有的参数都放置完毕，然后执行 `call` 指令
#### x86-64 函数调用约定
- 参数 **可以** 通过寄存器传递（这样比通过栈传递参数效率更高，它避免了内存中参数的存取和额外的指令）
- 根据参数类型的不同，会使用寄存器传参或栈传参
	- 如果参数的类型是 `MEMORY`，则在栈上传参
	- 如果参数的类型是 `INTEGER`，则顺序使用`rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9` 传参，若参数数量多于 6 个，则后面的参数在栈上传递
## 核心转储
当程序运行的过程中出现异常终止或崩溃、系统将会将程序崩溃时的内存、寄存器状态、堆栈指针、内存管理信息等记录下来，保存在一个文件中，叫做 **核心转储（Core Dump）**
核心转储的信号

| 信号      | 动作   | 解释                  |
| ------- | ---- | ------------------- |
| SIGQUIT | Core | 通过键盘退出时             |
| SIGILL  | Core | 遇到不合法的指令时           |
| SIGABRT | Core | 从 abort 中产生的信号      |
| SIGSEGV | Core | 无效的内存访问             |
| SIGTRAP | Core | trace/breakpoint 陷阱 |
**命令**
`ulimit -c` 默认关闭核心转储
`ulimit -c unlimited` 临时开启核心转储
`cat /etc/securite/limits.conf` 将 `value 0` 修改为 `unlimited` 永久开启
## 系统调用
系统调用是一些内核空间函数，是用户空间访问内核的唯一手段
这些函数与 CPU 架构有关，x86 提供了 358 个系统调用，x86-64 提供了 322 个系统调用
- 早期 2.6 及更早版本的内核使用 **软中断 `int 0x80`** 机制进行系统调用，但是因其性能较差，在往后的内核中被 **快速系统调用指令** 替代
- 32 位系统使用 `sysenter` （对应 `sysexit`）指令，需要为其手动布置栈
- 64 位系统使用 `syscall` （对应 `sysret`）指令
一般情况下，应用程序通过在 **用户空间** 实现的 **应用编程接口（API）** 而不是系统调用来编程，这些接口很多都是系统调用的封装
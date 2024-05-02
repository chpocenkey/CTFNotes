**Stack Canaries** 是一种用于对抗 **栈溢出攻击** 的技术，即 **SSP安全机制**，有时也叫作 **Stack cookies**
**原理**
Canary 的值是 **栈** 上的一个 **随机数**，在 **程序启动** 时 **随机** 生成并保存在 **比函数返回地址更低** 的位置。由于栈溢出是从低地址到高地址进行覆盖，因此攻击者要想控制函数的返回指针，就一定要先覆盖到 Canary。程序只需要在函数返回前检查 Canary 是否被篡改，就可以达到 **保护栈** 的目的
## 简介
Canaries 通常可分为三类：terminator、random 和 random XOR，具体的实现有 StackGuard、StackShield、ProPoliced 等，其中，StackGuard 出现于 1997 年，是 Linux 最初的实现方式
- **Termiantor Canaries：** 由于许多栈溢出都是因为字符串操作不当所产生的，而这些字符串以 **截断字符** NULL `\x00` 结尾，所以将低位 Canary 设置为 `\x00`，即可以防止泄露，也可以防止被伪造。截断字符还包括 CR `0x0d`、LF `0x0a`、EOF `0xff`
- **Random Canaries：** 为了防止 Canaries 被攻击者猜到，Random Canaries 在程序初始化时随机生成（通常由 `/dev/urandom` 生成，有时也用当前时间的哈希），并保存在一个相对安全的地方
- **Random XOR Canaries：** 于 Random Canaries 类似，但多了一个 XOR 操作，这样无论是 Canaries 被篡改还是与之 XOR 的控制数据被篡改，都会发生错误，这增加了攻击难度
## GCC 编译指令

| 指令                           | 意义                                  |
| ---------------------------- | ----------------------------------- |
| `-fstack-protector`          | 对 `alloca` 系列函数和内部缓冲区大于 8 字节的函数启用保护 |
| `-fstack-protector-strong`   | 增加对局部数组定义和地址引用函数的保护                 |
| `-fstack-protextor-all`      | 对所有函数启用保护                           |
| `-fstack-protector-explicit` | 对包含 `stack_protect` 属性的函数启用保护       |
| `-fno-stack-protector`       | 禁用保护                                |
## TLS
在 Linux 中 `fs` 寄存器被用于存放 **线程局部存储（Thread Locak Storage，TLS）**，TLS 主要是为了避免多个线程同时访问同一全局变量或静态变量时所导致的冲突
TLS 为每个使用该全局变量的线程都提供了一个变量值的 **副本**，每个线程可以独立地改变字节的副本，而不会和其他线程的副本冲突
从 TLS 中去除 Canary 后，程序将其插入 `rbp-0x8` 的位置暂存，在函数返回前，又从栈上将其取出，与 TLS 中的 Canary 进行异或比较以确定是否相等
- 64 位程序在 `glibc` 的实现里，TLS 结构体 `tcbhead_t` 的偏移为 `0x28` 处为 `stack_guard`
- 32 位程序在 `gs` 寄存器偏移 `0x14` 处

## 实现（以 64 位程序为例）
在程序加载时通过 `arch_prctl` 系统调用使 `glibc` 中的 `ld.so` 初始化 TLS，包括为其分配空间以及设置 `fs` 寄存器指向 TLS，然后程序调用 `security_init()` 函数（`__libc_start_main()` 函数也可以）生成 Canary 的值 `stack_chk_guard` 并放入 `stack_guard` 处（`fs:0x28`）
1. 进入 `security_init()` 函数或 `__libc_start_main()` 函数
2. 通过 `__dl_random` 指向一个由内核提供的随机数或由 `glibc` 自己产生随机数
3. 进入 `_dl_setup_stack_chk_guard()` 函数，并根据位数（32 或 64）以及字节序生成相应的 Canary 值（Canary 的最低位被设置为 `0x00`，且若 `dl_random` 指针为 NULL，则 Canary 为定值
4. 程序将生成的 Canary 交给 THREAD_SET_STACK_GUARD 宏处理，宏中 THREAD_SETMEM 可以直接修改线程描述符成员，其参数 THREAD_SELF 就是当前线程的线程描述符
5. 执行完毕后，Canary 值被放到 `fs:0x28` 的位置，程序运行时即可去除使用（若程序没有定义 THREAD_SET_STACK_GUARD 宏，则会将 Canary 值直接赋给 `__stack_chk_guard`，这是一个全局变量，放在 `.bss` 段中
## 攻击
攻击 Canaries 的主要目的是 **避免程序崩溃**，有两种思路
- 将 Canaries 的值泄露出来，然后在栈溢出时覆盖上去，使其保持不变
- 同时篡改 TLS 和栈上的 Canaries，保证在检查时能通过
以下是一些示例

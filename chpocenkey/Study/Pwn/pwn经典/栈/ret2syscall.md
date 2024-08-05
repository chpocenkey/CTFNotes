## 原理

控制程序执行系统调用，获得 `shell`

## 详解

## 特点

构造 `payload` 时有两种方式构造

- 溢出后的返回地址是 `system` 的地址，也就是 `plt` 表中的 `system` 的地址
- 溢出后的返回地址是 `call system` 的地址，是程序中出现过的调用 `system` 的地址

直接调用 `system` 的 `plt` 地址时，需要在 `system` 地址后面接上一个返回地址，再接上需要传递给 `system` 函数的参数

但是如果调用的是 `call system` ，可以直接传递参数，而不需要添加返回地址，因为调用 `call system` 会在返回到 `call system` 后才执行 `system_addr` 返回地址，也就不需要在构造上费心思
# 解题技巧

1. `check` 检测程序开启的保护
2. 使用 `IDA` 对程序进行反编译
3. 查看程序漏洞，发现字符串的写入
4. 查看字符串写入的位置，是在 `.bss` 段
5. 通过 `gdb` 中的 `vmmap` 查看 `.bss` 段是否为可写可执行

## 例题

- [[pwn39 32位 ret2syscall]]
- [[pwn40 64位 ret2syscall]]
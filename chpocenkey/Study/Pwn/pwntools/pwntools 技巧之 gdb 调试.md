**参考链接：** [`pwnlib.gdb` — 配合 GDB 一起工作](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/gdb.html)
在漏洞利用的编写中，会非常频繁使用到 GDB 来调试目标二进制程序
# 有用的函数

| 函数                  | 作用                                      |
| ------------------- | --------------------------------------- |
| `attach()`          | 附加到一个已存在的进程                             |
| `debug()`           | 在调试器下启动一个新进程，并且停在第一条指令                  |
| `debug_shellcode()` | 通过提供的 `shellcode` 来构建一个二进制程序，并且在调试器中启动它 |
## 调试技巧
### 附加至进程
使用 `attach()` 附加到已存在进程，`attach()` 函数非常有用，可以用它调试一个单独的二进制文件，也可以在提供一个 `remote` 对象的前提下，自动地在分支服务中找到正确的进程
### 产生新进程
如果需要从更早的指令地址开始调试一个进程，你需要使用 `debug`
使用 `debug` 时，它的返回值是一个你可以正常交互的 `tube` 对象
### Kernel Yama ptrace_scope
Linux 核心自 `v3.4` 版本开始引入一个安全机制叫作 `ptrace_scope`，它用来阻止进程之间的相互调试，除非进程间有直接的父子关系。这导致正常的 pwntools 工作流产生了一些问题

```
python ---> target
       `--> gdb
```
`python` 是 `target` 的父进程，但不是 `gdb` 的父进程
为了避免这个问题，`pwntools` 使用了一个函数 `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`，它会对 `pwntools` 中所有通过 `process()` 或 `ssh.process()` 产生的进程禁用 YAMA
旧版本的 `pwntools` 无法执行 `prctl` 步骤，并且需要在全系统范围内禁用 Yama 安全功能，而这需要 `root` 访问权限
## 函数详解
##### `attach()`
**函数原型** 
`pwnlib.gdb.attach(_target_, _gdbscript = None_, _exe = None_, _arch = None_, _ssh = None_) → None`
**参数**
- **target** – The target to attach to.
- **gdbscript** ([`str`](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)") or [`file`](https://docs.python.org/2.7/library/functions.html#file "(在 Python v2.7)")) – GDB script to run after attaching.
- **exe** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – The path of the target binary.
- **arch** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – Architechture of the target binary. If exe known GDB will detect the architechture automatically (if it is supported).
- **gdb_args** ([_list_](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/protocols/adb.html#pwnlib.protocols.adb.AdbClient.list "pwnlib.protocols.adb.AdbClient.list")) – List of additional arguments to pass to GDB.
- **sysroot** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – Foreign-architecture sysroot, used for QEMU-emulated binaries and Android targets.
**返回值**
gdb 进程（或正在运行的窗口）的 pid

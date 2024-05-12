**参考链接：** [`pwnlib.gdb` — 配合 GDB 一起工作](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/gdb.html)
在漏洞利用的编写中，会非常频繁使用到 GDB 来调试目标二进制程序
## 常用的函数

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
###### 函数原型
`pwnlib.gdb.attach(_target_, _gdbscript = None_, _exe = None_, _arch = None_, _ssh = None_) --> None`
###### 参数
- **target** – The target to attach to.
- **gdbscript** ([`str`](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)") or [`file`](https://docs.python.org/2.7/library/functions.html#file "(在 Python v2.7)")) – GDB script to run after attaching.
- **exe** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – The path of the target binary.
- **arch** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – Architechture of the target binary. If exe known GDB will detect the architechture automatically (if it is supported).
- **gdb_args** ([_list_](https://pwntools-docs-zh.readthedocs.io/zh-cn/dev/protocols/adb.html#pwnlib.protocols.adb.AdbClient.list "pwnlib.protocols.adb.AdbClient.list")) – List of additional arguments to pass to GDB.
- **sysroot** ([_str_](https://docs.python.org/2.7/library/functions.html#str "(在 Python v2.7)")) – Foreign-architecture sysroot, used for QEMU-emulated binaries and Android targets.
###### 返回值
gdb 进程（或正在运行的窗口）的 pid
###### 备注
`target` 参数非常强大，可以有各种不同的输入方式：
- `int` 作为进程的 PID
- `str` 作为进程的名称
- `tuple` 作为监听 `gdbserver` 的端口
- `process` 作为想要连接的进程
- `sock` 作为连接的套接字，可以以 `listen` 或 `remote` 等套接字类型作为参数
- `ssh_channel` 通过 `ssh.process()` 远程连接进程
###### 示例
```
# 连接 PID 为 1234 的进程
gdb.attach(1234)
```

```
# 连接进程名为 bash 的进程
gdb.attach('bash')
```

```
# 开始一个进程
bash = process('bash')

# 开始调试
gsb.attach(bash, '''
set follow-fork-mode child
break execve
continue
''')

# 与进程交互
bash.sendline('whoami')
```

```
# 开始一个 forking 服务
server = process(['socat', 'tcp-listen:1234,fork,reuseaddr', 'exec:/bin/sh'])

# Connect to the server
io = remote('localhost', 1234)

# Connect the debugger to the server-spawned process
gdb.attach(io, '''
break exit
continue
''')

# Talk to the spawned 'sh'
io.sendline('exit')
```

```
# Connect to the SSH server
shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)

# Start a process on the server
cat = shell.process(['cat'])

# Attach a debugger to it
gdb.attach(cat, '''
break exit
continue
''')

# Cause `cat` to exit
cat.close()
```


##### `binary()`
###### 函数原型
`pwnlib.gdb.binary() --> str`
###### 返回值
- `str` `gdb` 程序的路径
###### 示例
```
>>> gdb.binary() 
'/usr/bin/gdb'
```
##### `corefile()`
###### 函数原型
`pwnlib.gdb.corefile(process) --> core`
###### 参数
- `process` 想要转储的进程
###### 返回值
- `core` 生成的核心文件
##### `debug()`
###### 作用
先用指定命令行创建一个 `gdb` 服务，然后运行 `gdb` 并将其附着在它上面
###### 函数原型
`pwnlib.gdb.debug(args) --> tube`
###### 参数
- `args(list)` 进程的参数，近似于 `process` 进程
- `gdbscript(str)` 要运行的 `gdb` 脚本
- `exe(str)` 磁盘中可执行文件的位置
- `env(dict)` 二进制文件要运行的环境
- `ssh(ssh)` 用于启动进程的远程 `ssh` 会话
- `sysroot(str)` 国外架构系统根，用于 QEMU 仿真二进制文件和 Android 目标机
###### 返回值
`process` 或 `ssh_channel` 连接到目标进程的管道
###### 备注
###### 示例
```
# Create a new process, and stop it at 'main'
io = gdb.debug('bash', '''
break main
continue
''')

# Send a command to Bash
io.sendline("echo hello")

# Interact with the process
io.interactive()
```

```
# Create a new process, and stop it at 'main'
io = gdb.debug('bash', '''
# Wait until we hit the main executable's entry point
break _start
continue

# Now set breakpoint on shared library routines
break malloc
break free
continue
''')

# Send a command to Bash
io.sendline("echo hello")

# Interact with the process
io.interactive()
```

```
# Connect to the SSH server
shell = ssh('passcode', 'pwnable.kr', 2222, password='guest')

# Start a process on the server
io = gdb.debug(['bash'],
                ssh=shell,
                gdbscript='''
break main
continue
''')

# Send a command to Bash
io.sendline("echo hello")

# Interact with the process
io.interactive()
```
##### `debug_assemble()`
###### 作用
创建一个 ELF 文件，并用调试器运行它
这与 `debug_shellcode` 相同，只是在 `gdb` 中可以使用任何已定义的符号，而且可以省去显式调用 `asm()`
###### 参数
- `asm(str)` 
###### 返回值
- `process`
###### 示例
```
assembly = shellcraft.echo("Hello world!")
io = gdb.debug_assembly(assembly)
io.recvline() 
# ‘Hello world!’
```

##### `debug_shellcode()`
###### 作用
创建一个 ELF 文件，并在调试器下启动它
###### 函数原型
`pwnlib.gdb.debug_shellcode(*a, **kw)`
###### 参数
- `data(str)` 组装的 `shellcode` 字节
- `gdbscript(str)` 要在 `gdb` 运行的脚本
- `vma(int)` 在 `**kw` 处加载的 `shellcode` 的基址
- `args` 重写任何 `pwnlib.context.context` 的值
###### 返回值
`process` 进程
###### 示例
```
assembly = shellcraft.echo("Hello world!")
shellcode = asm(assembly)
io = gdb.debug_shellcode(shellcode)
/;io.recvline()
# ‘Hello world!’
```
##### `find_module_addresses()`
###### 函数原型
`pwnlib.gdb.find_module_addresses(_binary_, _ssh=None_, _ulimit=False_)`
###### 参数
- `binary(str)` 在远程服务上二进制文件的路径
- `ssh(pwnlib.tubes.tube)` 用于加载库的 SSH 连接。如果值为 `None`，则将使用 `pwnlib.tubes.process.process`
- `ulimit(bool)` 设置为 `True` 时在 `gdb` 之前运行 `ulimit -s unlimited`
###### 返回值
带有正确基地址的 `pwnlib.elf.ELF` 对象列表
###### 示例
```
>>> with context.local(log_level=9999): 
...     shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0', port=2220)
...     bash_libs = gdb.find_module_addresses('/bin/bash', shell)
>>> os.path.basename(bash_libs[0].path) 
'libc.so.6'
>>> hex(bash_libs[0].symbols['system']) 
'0x7ffff7634660'
```
##### `version()`
获得 `gdb` 的版本信息
###### 函数原型
`pwnlib.gdb.version(program='gsb')`
###### 返回值
`tuple` 一个包括版本信息的元组
###### 示例
```
>>> (7,0) <= gdb.version() <= (8,0)
True
```

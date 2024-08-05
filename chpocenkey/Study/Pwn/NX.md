## 介绍
No-eXecute，拒绝执行。
NX 的基本原理是将数据所在内存页（用户栈中）标识为不可执行，当程序溢出成功转入 shellcode 时，程序会尝试在数据页面上执行指令，此时 CPU 会抛出异常，而不是去执行恶意指令
最早的缓冲区溢出攻击，直接再内存栈中写入 shellcode 然后覆盖 EIP 指向这段 shellcode 去执行，所以 NX 即 No-eXecute（不可执行）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入 shellcode 时，程序会尝试在数据页面上执行指令
### 保护
可以阻止 `return2shellcode` 攻击
### 缺陷
`return2libc` , `ROP` , `Hijack GOT` 等攻击依然有效
### NX 保护的开启
`gcc -m32 -g -ggdb -fno-stack-protector -no-pie 1.c -o task2`
### 基础知识
##### 1. linux_64 与 linux_86 的区别
- x64 的内存地址为 64 位，但可以使用的内存地址不能大于 0x00007ffffffffff，否则会抛出异常
- x86 中参数通过栈传递，x64 中前六个参数依次保存在 RDI，RSI，RDX，RCX，R8，R9 寄存器中，如果有更多的参数则保存在栈上
##### 2. 函数调用约定
描述参数如何传递及由谁平衡堆栈（进函数前还是进函数后），以及返回值
```
_stdcall（windowsAPI 默认调用方式）
_cdecl（C/C++ 默认调用方式
_fastcall
_thiscall
```
# NX 绕过
## ROP 绕过 NX
### 原理
1. 当程序运行到 `gadget_addr` 时（`rsp` 指向 `gadget_addr`），接下来会跳转到利用的小片段里执行命令，同时 `rsp+8`（`rsp` 指向 `bin_sh_addr`）
2. 执行 `pop rdi`，将 `bin_sh_addr` 弹入 `rdi` 寄存器中，同时 `rsp+8`（`rsp` 指向 `system_addr`）
3. 执行 `return` 指令，因为此时 `rsp` 指向 `system_addr`，这时就会调用 `system` 函数，而参数通过 `rdi` 传递，也就是会将 `/bin/sh` 传入，从而实现调用 `system('/bin/sh')`
### 需要解决的问题                                                                                                                                                                                                 
- `gadget_addr` 的寻找
- `/bin/sh` 字符串如何得到，通常程序没有这样的字符串
- `libc` 中 `system` 实际运行的地址，即 `libc` 的基地址 `+` `system` 在 `libc` 中的偏移地址
- 确定返回地址 `return_addr` 前面的缓冲区有多大，这样才能准确的实现缓冲区溢出覆盖
### 解决方案
#### 1. `gadget_addr` 的寻找
`gadget_addr` 指向的是程序中可以利用的小片段汇编代码，如 `pop` 加 `ret` 组合
可以使用如下工具：
- ROPgadget
#### 2. `/bin/sh` 字符串的获得
- 首先搜索程序中是否存在这样的字符串，通常情况下是没有的
- 在程序某处写入这样的字符串供我们利用
通常将这个字符串写入 `.bss` 段，使用可写入的函数

	read、scanf、gets
`.bss` 段是用来保存全局变量的值，地址固定，并且可读可写
通过 `readelf -S pwnme` 命令可以获取 `.bss` 段的地址
#### 3. `system` 函数的获得
- 首先查看程序中是否有可以利用的子函数
- 通过泄露 `libc` 函数，获取可利用的函数
泄露一个 `libc` 函数的地址需要使用一个能输出的函数

	write、printf、puts
	泄露一个 libc 函数的地址 => 由 libc.so 文件得知的相对偏移地址 => libc 基地址 => 其它任意 libc 函数的真实地址
由于 `libc` 的延迟绑定机制，需要选择已经执行过的函数进行泄露
### 实现框架
#### 基础思路
1. 通过泄露一些函数的真实地址结合相对偏移得到 `system` 函数的真实地址
2. 控制程序再次执行到缓冲区溢出漏洞点
3. 利用缓冲区溢出漏洞，写入 `/bin/sh\0` 字符串到 `.bss`，并触发 `system` 执行
#### 实现思路
- 使用 pwntool 的 DynELF 作为泄露的工具
- 自己编写两个 payload 完成利用流程，第一个 payload 完成泄露并再次到漏洞函数执行。第二个 payload 执行写入 `/bin/sh` 字符串到 `.bss` 并让程序调用 `system` 得到 `shell`
#### DynELF leak 原理解析
DynELF 是 pwntool 的一个模块，要使用该模块，最重要的是编写 leak 函数。只要将 leak 函数编写好，只需调用对象相应的方法，pwntool 会自动完成泄露工作

##### DynELF 实例
```
from pwn import *
elf = ELF('./level2')
write_plt = elf.symbols['write']
read_plt = elf.symbols['read']

def leak(address):
	payload1 = b'a'*140 + p32(write_plt) + p32(vuln) + p32(1) + p32(address) + pew(4)
	p.send(payload1)
	data = p.recv(4)
	print("%#x => %s", %(address, (data or ' ').encode('hex')))
	return data
p = process('./level2')
d = DynELF(leak, elf=ELF('./level2'))
system_addr = d.lookup('system', 'libc')
print("system_addr=" + hex(system_addr))
```
- 官方给的 leak 说明是需要出入一个地址，然后放回至少一个字节的该地址内容（leak 的外部特性）
- `b'a'*140` 刚好覆盖完缓冲区的情况，后面的内容将开始写入该漏洞执行完
- `write_plt` 使用 `ELF` 的 `symbols` 获得，但是这样并不准确，建议使用 `gdb` 看 `call write@plt` 那一行后面显示的地址
- `vuln` 是漏洞函数的内部第一句汇编代码的地址
- `1` 是 `write` 需要的三个参数的第一个参数，即表示写入到 `stdout`
- `address` 是需要读取的地址
- `4` 是字节数，是 `write` 的第三个参数

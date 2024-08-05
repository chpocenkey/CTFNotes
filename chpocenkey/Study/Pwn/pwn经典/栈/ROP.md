返回导向编程（Return Oriented Programming），其主要思想为在栈缓冲区溢出的基础上，利用程序中已有的小片段（gadgets）来改变某些寄存器或者变量的值，从而控制程序的执行流程。利用指令集中的 `ret` 指令，从而改变了指令流的执行顺序，并通过数条 `gadgets` 执行一个新的程序

`gadgets` 通常是以 `ret` 结尾的指令序列

## 攻击条件

- 程序漏洞允许劫持控制流，并控制后续的返回地址
- 可以找到满足条件的 `gadgets` 以及相应 `gadgets` 的地址

## 现代防护

- 地址随机化保护（ASLR）， `gadgets` 在内存中的未知是不固定的。但是其相对于对应段基址的偏移是固定的，因此可以在找到合适 `gadgets` 后通过其他方式泄露程序运行环境信息从而计算出 `gadgets` 在内存中的真正地址
## 方式
### 初级

- [[ret2text]]
- [[ret2shellcode]]
- [[ret2syscall]]
- [[ret2libc]]
### 中级

- [[ret2csu]]
- [[ret2reg]]
- [[JOP]]
- [[COP]]
- [[BROP]]

### 高级

- [[ret2dlresolve]]
- [[ret2VDSO]]
- [[SROP]]
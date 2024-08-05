由于 C 语言对数组引用不做任何边界检查，从而导致缓冲区溢出（buffer overflow）成为一种很常见的漏洞，根据溢出发生的内存位置，通常可以分为 **栈溢出** 和 **堆溢出**
**栈溢出** 由于栈上保存着局部变量和一些状态信息（寄存器值、返回地址等），一旦发生严重的溢出，攻击者就可以通过 **复写返回地址** 来执行 **任意代码**，利用方式包括 `shellcode` 注入、 `ret2libc` 、ROP 等
## 函数调用栈
函数调用栈是一块连续的用来保存函数运行状态的内存区域，调用函数（caller）和被调用函数（callee）根据调用关系堆叠起来，从内存的高地址向低地址增长。这个过程主要涉及三个寄存器：
- `eip` / `rip` 用于存储即将执行的指令地址
- `esp` / `rsp` 用于存储栈顶地址，随着数据的压栈和出栈而变化
- `ebp` / `rbp` 用于存储栈基址，并参与栈内数据的寻址

在 64 位，根据 AMD64 ABI 文档的描述，`rsp` 以下 128 字节的区域被称为 red zone，这是一块被保留的内存，不会被信号或中断所修改，所以叶子函数可以在不调整栈指针（不下移 `rsp` 开辟栈空间）的情况下，使用这块内存保存临时数据。这是一项 **编译优化**

在更极端的 **优化** 下，`rbp` 作为栈基址也可以省略，编译器完全可以使用 `rsp` 来代替，从而减少指令数量
## 危险函数
- `scanf`、`gets` 等输入读取函数
- `strcpy`、`strcat`、`sprintf` 等字符串拷贝函数
## `shellcode` 注入
在没有 NX 保护机制的时候，在栈溢出的同时就可以将 `shellcode` 注入栈上并执行。使输入一直覆盖到调用者的 `ebp` / `rbp`，然后在返回地址处填充上 `shellcode` 的地址，当函数返回时，就会跳到 `shellcode` 的位置
开启了 ASLR，使 `shellcode` 的地址不确定，则可以使用 NOP sled（`\x90\x90`）作为一段滑板指令，当程序跳到这段指令时，就会一直滑到 `shellcode` 执行
## `ret2libc`
开启 NX 保护时，栈上的 `shellcode` 不可执行，此时需要使用 `ret2libc` 调用 `libc.so` 中的 `system("/bin/sh")`，在返回地址覆盖上 `system()` 函数的地址。再添加 `"/bin/sh"` 字符串的地址作为参数
开启了 ASLR，则需要先做内存泄漏，再填充真实地址
## ROP
返回导向编程（Return-Oriented Programming，ROP），无须调用任何函数即可执行任意代码
使用 ROP 攻击，首先需要扫描文件，提取出可用的 `gadget` 片段（通常以 `ret` 指令结尾），然后将这些 `gadget` 根据所需要的功能进行组合，达到攻击者的目的
由于 `gadget` 片段在地址上不一定是连续的，所以需要通过 `ret` 指令进行连接，依次执行
### `ret` 指令的作用
- 通过间接跳转改变执行流
- 更新寄存器状态
### 工具 
ROPgadget、Ropper等，可以直接在 [ropshell](http://www.ropshell.com/) 网站上搜索
###### 程序
- ROPgadget
- Ropper
###### 网站
-  [ropshell](http://www.ropshell.com/)
- scoding.de
### 用法
- 保存栈数据到寄存器：`pop eax; ret;`
- 保存内存数据到寄存器：`mov ecx, [eax]; ret;`
- 保存寄存器数据到内存：`mov [eax], ecx; ret;`
- 算数和逻辑运算：`add eax, ebx; ret;`
- 系统调用：`int 0x80; ret;` `call gs:[0x10]; ret;`
- 影响栈帧（改变 `ebp` 的值）：`leave; ret;` `pop ebp; ret;`
## ROP的变种（不依赖 `ret` 指令）
以 `jmp` 指令代替 `ret` 指令作为结尾，被称为 JOP（Jump-Oriented Programming）
它的行为与 `ret` 很像，唯一的副作用是覆盖了 `eax` 寄存器。如果程序执行不依赖于 `eax`，则这段指令可以取代 `ret`
单间接跳转
`pop %eax; jmp *%eax;`
双重间接跳转
`pop %eax; jmp *(%eax);`
此时 `eax` 存放一个被称为 `sequence catalog` 表的地址，该表用于存放各种指令序列的地址。双重间接跳转就是先从上一段指令序列跳到 `catalog` 表，然后从 `catalog` 表跳到下一段指令序列
## Blind ROP
BROP（Blind Return Oriented Programming）能够在无法获得二进制程序的情况下，基于远程服务崩溃与否（连接是否中断），进行 ROP 攻击获得 `shell`
### 条件
- 目标程序存在栈溢出漏洞，并且可以稳定触发
- 目标进程在崩溃后会立即重启，并且重启后的进程内存不会重新随机化
- 如果在编译时同时启用了 `ASLR` 和 `PIE`，则服务器必须是一个 `fork` 服务器，并且在重启时不使用 `execve`
### BROP 攻击的主要阶段
1. Stack reading：泄露 Canaries 和返回地址，然后从返回地址可以推算出程序的加载地址，用于后续 gadgets 的扫描。泄露方法是遍历所有 256 个数，每溢出一个字节根据程序是否崩溃来判断溢出值是否正确
2. Bling ROP：用于远程搜索 `gadgets`，目标是将目标程序从内存写到 `socket`，传回攻击者本地
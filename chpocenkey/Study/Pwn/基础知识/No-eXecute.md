No-eXecute（NX），表示不可执行
通常使用 **可执行空间保护（executable space protection）** 作为一个统称没来描述这种防止传统代码注入攻击的技术——攻击者将恶意代码注入正在运行的程序中，然后使用内存损坏漏洞将控制流重定向到该代码
实施这种保护的技术有多种名称，在 Windows 称为 **数据保护执行（DEP）**，在 Linux 上则有 NX、W-X、PaX 和 Exec Shield 等 
**原理**
将数据所在的内存页（通常为堆栈）标识为不可执行，如果程序产生溢出转入执行 shellcode 时，CPU 将会抛出异常
**实现**
NX 的实现需要结合软件和硬件共同完成
**硬件**
利用处理器的 NX 位，对相应页表项中的 **第 63 位** 进行设置，设置为 1 表示内容不可执行，设置为 0 表示内容可执行
当 **程序计数器（PC）** 被放到受保护的页面内时，就会除法硬件层面的异常
**软件**
操作系统需要支持 NX，以便正确 **配置页表**
但此操作可能带来一些问题，此时需要使用适当的 API 来分配内存，如 Windows 上使用 `VirtualProtect` 或 `VirtualAlloc`，Linux 上使用 `mprotect` 或 `mmap`，这些 API 允许更改已分配页面的保护级别

在 Linux 中，当 **装载器** 将程序装载进内存空间后，将程序的 `.text` 节标记为 **可执行**，而其余的数据段以及堆栈均为 **不可执行**，因此，传统的通过修改 GOT 来执行 `shellcode` 的方式不再可行
但 NX 这种保护不能阻止 **代码重用** 攻击（`ret2libc`）

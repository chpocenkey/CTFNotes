# 全功能的二进制文件分析工具 Radare2 指南

> Radare2 是一个为二进制分析定制的开源工具。

在《[Linux 上分析二进制文件的 10 种方法](https://linux.cn/article-12187-1.html)》中，我解释了如何使用 Linux 上丰富的原生工具集来分析二进制文件。但如果你想进一步探索你的二进制文件，你需要一个为二进制分析定制的工具。如果你是二进制分析的新手，并且大多使用的是脚本语言，这篇文章《[GNU binutils 里的九种武器](https://linux.cn/article-11441-1.html)》可以帮助你开始学习编译过程和什么是二进制。

### 为什么我需要另一个工具？

如果现有的 Linux 原生工具也能做类似的事情，你自然会问为什么需要另一个工具。嗯，这和你用手机做闹钟、做笔记、做相机、听音乐、上网、偶尔打电话和接电话的原因是一样的。以前，使用单独的设备和工具处理这些功能 —— 比如拍照的实体相机，记笔记的小记事本，起床的床头闹钟等等。对用户来说，有一个设备来做多件（但相关的）事情是_方便的_。另外，杀手锏就是独立功能之间的_互操作性_。

同样，即使许多 Linux 工具都有特定的用途，但在一个工具中捆绑类似（和更好）的功能是非常有用的。这就是为什么我认为 [Radare2](https://rada.re/n/) 应该是你需要处理二进制文件时的首选工具。

根据其 [GitHub 简介](https://github.com/radareorg/radare2)，Radare2（也称为 r2）是一个“类 Unix 系统上的逆向工程框架和命令行工具集”。它名字中的 “2” 是因为这个版本从头开始重写的，使其更加模块化。

### 为什么选择 Radare2？

有大量（非原生的）Linux 工具可用于二进制分析，为什么要选择 Radare2 呢？我的理由很简单。

首先，它是一个开源项目，有一个活跃而健康的社区。如果你正在寻找新颖的功能或提供着 bug 修复的工具，这很重要。

其次，Radare2 可以在命令行上使用，而且它有一个功能丰富的图形用户界面（GUI）环境，叫做 Cutter，适合那些对 GUI 比较熟悉的人。作为一个长期使用 Linux 的用户，我对习惯于在 shell 上输入。虽然熟悉 Radare2 的命令稍微有一点学习曲线，但我会把它比作 [学习 Vim](https://opensource.com/article/19/3/getting-started-vim)。你可以先学习基本的东西，一旦你掌握了它们，你就可以继续学习更高级的东西。很快，它就变成了肌肉记忆。

第三，Radare2 通过插件可以很好的支持外部工具。例如，最近开源的 [Ghidra](https://ghidra-sre.org/) 二进制分析和逆向工具reversing tool很受欢迎，因为它的反编译器功能是逆向软件的关键要素。你可以直接从 Radare2 控制台安装 Ghidra 反编译器并使用，这很神奇，让你两全其美。

### 开始使用 Radare2

要安装 Radare2，只需克隆其存储库并运行 `user.sh` 脚本。如果你的系统上还没有一些预备软件包，你可能需要安装它们。一旦安装完成，运行 `r2 -v` 命令来查看 Radare2 是否被正确安装：

1. `$ git clone https://github.com/radareorg/radare2.git`
2. `$ cd radare2`
3. `$ ./sys/user.sh`

5. `# version`

7. `$ r2 -v`
8. `radare2 4.6.0-git 25266 @ linux-x86-64 git.4.4.0-930-g48047b317`
9. `commit: 48047b3171e6ed0480a71a04c3693a0650d03543 build: 2020-11-17__09:31:03`
10. `$`

#### 获取二进制测试样本

现在 `r2` 已经安装好了，你需要一个样本二进制程序来试用它。你可以使用任何系统二进制文件（`ls`、`bash` 等），但为了使本教程的内容简单，请编译以下 C 程序：

1. `$ cat adder.c`

1. `#include <stdio.h>`

3. `int adder(int num) {`
4.         `return num + 1;`
5. `}`

7. `int main() {`
8.         `int res, num1 = 100;`
9.         `res = adder(num1);`
10.         `printf("Number now is  : %d\n", res);`
11.         `return 0;`
12. `}`

1. `$ gcc adder.c -o adder`
2. `$ file adder`
3. `adder: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9d4366f7160e1ffb46b14466e8e0d70f10de2240, not stripped`
4. `$ ./adder`
5. `Number now is  : 101`

#### 加载二进制文件

要分析二进制文件，你必须在 Radare2 中加载它。通过提供文件名作为 `r2` 命令的一个命令行参数来加载它。你会进入一个独立的 Radare2 控制台，这与你的 shell 不同。要退出控制台，你可以输入 `Quit` 或 `Exit` 或按 `Ctrl+D`：

1. `$ r2 ./adder`
2.  `-- Learn pancake as if you were radare!`
3. `[0x004004b0]> quit`
4. `$`

#### 分析二进制

在你探索二进制之前，你必须让 `r2` 为你分析它。你可以通过在 `r2` 控制台中运行 `aaa` 命令来实现：

1. `$ r2 ./adder`
2.  `-- Sorry, radare2 has experienced an internal error.`
3. `[0x004004b0]>`
4. `[0x004004b0]>`
5. `[0x004004b0]> aaa`
6. `[x] Analyze all flags starting with sym. and entry0 (aa)`
7. `[x] Analyze function calls (aac)`
8. `[x] Analyze len bytes of instructions for references (aar)`
9. `[x] Check for vtables`
10. `[x] Type matching analysis for all functions (aaft)`
11. `[x] Propagate noreturn information`
12. `[x] Use -AA or aaaa to perform additional experimental analysis.`
13. `[0x004004b0]>`

这意味着每次你选择一个二进制文件进行分析时，你必须在加载二进制文件后输入一个额外的命令 `aaa`。你可以绕过这一点，在命令后面跟上 `-A` 来调用 `r2`；这将告诉 `r2` 为你自动分析二进制：

1. `$ r2 -A ./adder`
2. `[x] Analyze all flags starting with sym. and entry0 (aa)`
3. `[x] Analyze function calls (aac)`
4. `[x] Analyze len bytes of instructions for references (aar)`
5. `[x] Check for vtables`
6. `[x] Type matching analysis for all functions (aaft)`
7. `[x] Propagate noreturn information`
8. `[x] Use -AA or aaaa to perform additional experimental analysis.`
9.  `-- Already up-to-date.`
10. `[0x004004b0]>`

#### 获取一些关于二进制的基本信息

在开始分析一个二进制文件之前，你需要一些背景信息。在许多情况下，这可以是二进制文件的格式（ELF、PE 等）、二进制的架构（x86、AMD、ARM 等），以及二进制是 32 位还是 64 位。方便的 `r2` 的 `iI` 命令可以提供所需的信息：

1. `[0x004004b0]> iI`
2. `arch     x86`
3. `baddr    0x400000`
4. `binsz    14724`
5. `bintype  elf`
6. `bits     64`
7. `canary   false`
8. `class    ELF64`
9. `compiler GCC: (GNU) 8.3.1 20190507 (Red Hat 8.3.1-4)`
10. `crypto   false`
11. `endian   little`
12. `havecode true`
13. `intrp    /lib64/ld-linux-x86-64.so.2`
14. `laddr    0x0`
15. `lang     c`
16. `linenum  true`
17. `lsyms    true`
18. `machine  AMD x86-64 architecture`
19. `maxopsz  16`
20. `minopsz  1`
21. `nx       true`
22. `os       linux`
23. `pcalign  0`
24. `pic      false`
25. `relocs   true`
26. `relro    partial`
27. `rpath    NONE`
28. `sanitiz  false`
29. `static   false`
30. `stripped false`
31. `subsys   linux`
32. `va       true`

34. `[0x004004b0]>`
35. `[0x004004b0]>`

### 导入和导出

通常情况下，当你知道你要处理的是什么样的文件后，你就想知道二进制程序使用了什么样的标准库函数，或者了解程序的潜在功能。在本教程中的示例 C 程序中，唯一的库函数是 `printf`，用来打印信息。你可以通过运行 `ii` 命令看到这一点，它显示了该二进制所有导入的库：

1. `[0x004004b0]> ii`
2. `[Imports]`
3. `nth vaddr      bind   type   lib name`
4. `―――――――――――――――――――――――――――――――――――――`
5. `1   0x00000000 WEAK   NOTYPE     _ITM_deregisterTMCloneTable`
6. `2   0x004004a0 GLOBAL FUNC       printf`
7. `3   0x00000000 GLOBAL FUNC       __libc_start_main`
8. `4   0x00000000 WEAK   NOTYPE     __gmon_start__`
9. `5   0x00000000 WEAK   NOTYPE     _ITM_registerTMCloneTable`

该二进制也可以有自己的符号、函数或数据。这些函数通常显示在 `Exports` 下。这个测试的二进制导出了两个函数：`main` 和 `adder`。其余的函数是在编译阶段，当二进制文件被构建时添加的。加载器需要这些函数来加载二进制文件（现在不用太关心它们）：

1. `[0x004004b0]>`
2. `[0x004004b0]> iE`
3. `[Exports]`

5. `nth paddr       vaddr      bind   type   size lib name`
6. `――――――――――――――――――――――――――――――――――――――――――――――――――――――`
7. `82   0x00000650 0x00400650 GLOBAL FUNC   5        __libc_csu_fini`
8. `85   ---------- 0x00601024 GLOBAL NOTYPE 0        _edata`
9. `86   0x00000658 0x00400658 GLOBAL FUNC   0        _fini`
10. `89   0x00001020 0x00601020 GLOBAL NOTYPE 0        __data_start`
11. `90   0x00000596 0x00400596 GLOBAL FUNC   15       adder`
12. `92   0x00000670 0x00400670 GLOBAL OBJ    0        __dso_handle`
13. `93   0x00000668 0x00400668 GLOBAL OBJ    4        _IO_stdin_used`
14. `94   0x000005e0 0x004005e0 GLOBAL FUNC   101      __libc_csu_init`
15. `95   ---------- 0x00601028 GLOBAL NOTYPE 0        _end`
16. `96   0x000004e0 0x004004e0 GLOBAL FUNC   5        _dl_relocate_static_pie`
17. `97   0x000004b0 0x004004b0 GLOBAL FUNC   47       _start`
18. `98   ---------- 0x00601024 GLOBAL NOTYPE 0        __bss_start`
19. `99   0x000005a5 0x004005a5 GLOBAL FUNC   55       main`
20. `100  ---------- 0x00601028 GLOBAL OBJ    0        __TMC_END__`
21. `102  0x00000468 0x00400468 GLOBAL FUNC   0        _init`

23. `[0x004004b0]>`

### 哈希信息

如何知道两个二进制文件是否相似？你不能只是打开一个二进制文件并查看里面的源代码。在大多数情况下，二进制文件的哈希值（md5sum、sha1、sha256）是用来唯一识别它的。你可以使用 `it` 命令找到二进制的哈希值：

1. `[0x004004b0]> it`
2. `md5 7e6732f2b11dec4a0c7612852cede670`
3. `sha1 d5fa848c4b53021f6570dd9b18d115595a2290ae`
4. `sha256 13dd5a492219dac1443a816ef5f91db8d149e8edbf26f24539c220861769e1c2`
5. `[0x004004b0]>`

### 函数

代码按函数分组；要列出二进制中存在的函数，请运行 `afl` 命令。下面的列表显示了 `main` 函数和 `adder` 函数。通常，以 `sym.imp` 开头的函数是从标准库（这里是 glibc）中导入的：

1. `[0x004004b0]> afl`
2. `0x004004b0    1 46           entry0`
3. `0x004004f0    4 41   -> 34   sym.deregister_tm_clones`
4. `0x00400520    4 57   -> 51   sym.register_tm_clones`
5. `0x00400560    3 33   -> 32   sym.__do_global_dtors_aux`
6. `0x00400590    1 6            entry.init0`
7. `0x00400650    1 5            sym.__libc_csu_fini`
8. `0x00400658    1 13           sym._fini`
9. `0x00400596    1 15           sym.adder`
10. `0x004005e0    4 101          loc..annobin_elf_init.c`
11. `0x004004e0    1 5            loc..annobin_static_reloc.c`
12. `0x004005a5    1 55           main`
13. `0x004004a0    1 6            sym.imp.printf`
14. `0x00400468    3 27           sym._init`
15. `[0x004004b0]>`

### 交叉引用

在 C 语言中，`main` 函数是一个程序开始执行的地方。理想情况下，其他函数都是从 `main` 函数调用的，在退出程序时，`main` 函数会向操作系统返回一个退出状态。这在源代码中是很明显的，然而，二进制程序呢？如何判断 `adder` 函数的调用位置呢？

你可以使用 `axt` 命令，后面加上函数名，看看 `adder` 函数是在哪里调用的；如下图所示，它是从 `main` 函数中调用的。这就是所谓的交叉引用cross-referencing。但什么调用 `main` 函数本身呢？从下面的 `axt main` 可以看出，它是由 `entry0` 调用的（关于 `entry0` 的学习我就不说了，留待读者练习）。

1. `[0x004004b0]> axt sym.adder`
2. `main 0x4005b9 [CALL] call sym.adder`
3. `[0x004004b0]>`
4. `[0x004004b0]> axt main`
5. `entry0 0x4004d1 [DATA] mov rdi, main`
6. `[0x004004b0]>`

### 寻找定位

在处理文本文件时，你经常通过引用行号和行或列号在文件内移动；在二进制文件中，你需要使用地址。这些是以 `0x` 开头的十六进制数字，后面跟着一个地址。要找到你在二进制中的位置，运行 `s` 命令。要移动到不同的位置，使用 `s` 命令，后面跟上地址。

函数名就像标签一样，内部用地址表示。如果函数名在二进制中（未剥离的），可以使用函数名后面的 `s` 命令跳转到一个特定的函数地址。同样，如果你想跳转到二进制的开始，输入 `s 0`：

1. `[0x004004b0]> s`
2. `0x4004b0`
3. `[0x004004b0]>`
4. `[0x004004b0]> s main`
5. `[0x004005a5]>`
6. `[0x004005a5]> s`
7. `0x4005a5`
8. `[0x004005a5]>`
9. `[0x004005a5]> s sym.adder`
10. `[0x00400596]>`
11. `[0x00400596]> s`
12. `0x400596`
13. `[0x00400596]>`
14. `[0x00400596]> s 0`
15. `[0x00000000]>`
16. `[0x00000000]> s`
17. `0x0`
18. `[0x00000000]>`

### 十六进制视图

通常情况下，原始二进制没有意义。在十六进制模式下查看二进制及其等效的 ASCII 表示法会有帮助：

1. `[0x004004b0]> s main`
2. `[0x004005a5]>`
3. `[0x004005a5]> px`
4. `- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF`
5. `0x004005a5  5548 89e5 4883 ec10 c745 fc64 0000 008b  UH..H....E.d....`
6. `0x004005b5  45fc 89c7 e8d8 ffff ff89 45f8 8b45 f889  E.........E..E..`
7. `0x004005c5  c6bf 7806 4000 b800 0000 00e8 cbfe ffff  ..x.@...........`
8. `0x004005d5  b800 0000 00c9 c30f 1f40 00f3 0f1e fa41  .........@.....A`
9. `0x004005e5  5749 89d7 4156 4989 f641 5541 89fd 4154  WI..AVI..AUA..AT`
10. `0x004005f5  4c8d 2504 0820 0055 488d 2d04 0820 0053  L.%.. .UH.-.. .S`
11. `0x00400605  4c29 e548 83ec 08e8 57fe ffff 48c1 fd03  L).H....W...H...`
12. `0x00400615  741f 31db 0f1f 8000 0000 004c 89fa 4c89  t.1........L..L.`
13. `0x00400625  f644 89ef 41ff 14dc 4883 c301 4839 dd75  .D..A...H...H9.u`
14. `0x00400635  ea48 83c4 085b 5d41 5c41 5d41 5e41 5fc3  .H...[]A\A]A^A_.`
15. `0x00400645  9066 2e0f 1f84 0000 0000 00f3 0f1e fac3  .f..............`
16. `0x00400655  0000 00f3 0f1e fa48 83ec 0848 83c4 08c3  .......H...H....`
17. `0x00400665  0000 0001 0002 0000 0000 0000 0000 0000  ................`
18. `0x00400675  0000 004e 756d 6265 7220 6e6f 7720 6973  ...Number now is`
19. `0x00400685  2020 3a20 2564 0a00 0000 0001 1b03 3b44    : %d........;D`
20. `0x00400695  0000 0007 0000 0000 feff ff88 0000 0020  ...............`
21. `[0x004005a5]>`

### 反汇编

如果你使用的是编译后的二进制文件，则无法查看源代码。编译器将源代码转译成 CPU 可以理解和执行的机器语言指令；其结果就是二进制或可执行文件。然而，你可以查看汇编指令（的助记词）来理解程序正在做什么。例如，如果你想查看 `main` 函数在做什么，你可以使用 `s main` 寻找 `main` 函数的地址，然后运行 `pdf` 命令来查看反汇编的指令。

要理解汇编指令，你需要参考体系结构手册（这里是 x86），它的应用二进制接口（ABI，或调用惯例），并对堆栈的工作原理有基本的了解：

1. `[0x004004b0]> s main`
2. `[0x004005a5]>`
3. `[0x004005a5]> s`
4. `0x4005a5`
5. `[0x004005a5]>`
6. `[0x004005a5]> pdf`
7.             `; DATA XREF from entry0 @ 0x4004d1`
8. `┌ 55: int main (int argc, char **argv, char **envp);`
9. `│           ; var int64_t var_8h @ rbp-0x8`
10. `│           ; var int64_t var_4h @ rbp-0x4`
11. `│           0x004005a5      55             push rbp`
12. `│           0x004005a6      4889e5         mov rbp, rsp`
13. `│           0x004005a9      4883ec10       sub rsp, 0x10`
14. `│           0x004005ad      c745fc640000.  mov dword [var_4h], 0x64    ; 'd' ; 100`
15. `│           0x004005b4      8b45fc         mov eax, dword [var_4h]`
16. `│           0x004005b7      89c7           mov edi, eax`
17. `│           0x004005b9      e8d8ffffff     call sym.adder`
18. `│           0x004005be      8945f8         mov dword [var_8h], eax`
19. `│           0x004005c1      8b45f8         mov eax, dword [var_8h]`
20. `│           0x004005c4      89c6           mov esi, eax`
21. `│           0x004005c6      bf78064000     mov edi, str.Number_now_is__:__d ; 0x400678 ; "Number now is  : %d\n" ; const char *format`
22. `│           0x004005cb      b800000000     mov eax, 0`
23. `│           0x004005d0      e8cbfeffff     call sym.imp.printf         ; int printf(const char *format)`
24. `│           0x004005d5      b800000000     mov eax, 0`
25. `│           0x004005da      c9             leave`
26. `└           0x004005db      c3             ret`
27. `[0x004005a5]>`

这是 `adder` 函数的反汇编结果：

1. `[0x004005a5]> s sym.adder`
2. `[0x00400596]>`
3. `[0x00400596]> s`
4. `0x400596`
5. `[0x00400596]>`
6. `[0x00400596]> pdf`
7.             `; CALL XREF from main @ 0x4005b9`
8. `┌ 15: sym.adder (int64_t arg1);`
9. `│           ; var int64_t var_4h @ rbp-0x4`
10. `│           ; arg int64_t arg1 @ rdi`
11. `│           0x00400596      55             push rbp`
12. `│           0x00400597      4889e5         mov rbp, rsp`
13. `│           0x0040059a      897dfc         mov dword [var_4h], edi     ; arg1`
14. `│           0x0040059d      8b45fc         mov eax, dword [var_4h]`
15. `│           0x004005a0      83c001         add eax, 1`
16. `│           0x004005a3      5d             pop rbp`
17. `└           0x004005a4      c3             ret`
18. `[0x00400596]>`

### 字符串

查看二进制中存在哪些字符串可以作为二进制分析的起点。字符串是硬编码到二进制中的，通常会提供重要的提示，可以让你将重点转移到分析某些区域。在二进制中运行 `iz` 命令来列出所有的字符串。这个测试二进制中只有一个硬编码的字符串：

1. `[0x004004b0]> iz`
2. `[Strings]`
3. `nth paddr      vaddr      len size section type  string`
4. `―――――――――――――――――――――――――――――――――――――――――――――――――――――――`
5. `0   0x00000678 0x00400678 20  21   .rodata ascii Number now is  : %d\n`

7. `[0x004004b0]>`

### 交叉引用字符串

和函数一样，你可以交叉引用字符串，看看它们是从哪里被打印出来的，并理解它们周围的代码：

1. `[0x004004b0]> ps @ 0x400678`
2. `Number now is  : %d`

4. `[0x004004b0]>`
5. `[0x004004b0]> axt 0x400678`
6. `main 0x4005c6 [DATA] mov edi, str.Number_now_is__:__d`
7. `[0x004004b0]>`

### 可视模式

当你的代码很复杂，有多个函数被调用时，很容易迷失方向。如果能以图形或可视化的方式查看哪些函数被调用，根据某些条件采取了哪些路径等，会很有帮助。在移动到感兴趣的函数后，可以通过 `VV` 命令来探索 `r2` 的可视化模式。例如，对于 `adder` 函数：

1. `[0x004004b0]> s sym.adder`
2. `[0x00400596]>`
3. `[0x00400596]> VV`

![(Gaurav Kamathe, CC BY-SA 4.0)](https://img.linux.net.cn/data/attachment/album/202102/01/112635hqi5513d1e5bx8d8.png "(Gaurav Kamathe, CC BY-SA 4.0)")

_(Gaurav Kamathe, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/))_

### 调试器

到目前为止，你一直在做的是静态分析 —— 你只是在看二进制文件中的东西，而没有运行它，有时你需要执行二进制文件，并在运行时分析内存中的各种信息。`r2` 的内部调试器允许你运行二进制文件、设置断点、分析变量的值、或者转储寄存器的内容。

用 `-d` 标志启动调试器，并在加载二进制时添加 `-A` 标志进行分析。你可以通过使用 `db <function-name>` 命令在不同的地方设置断点，比如函数或内存地址。要查看现有的断点，使用 `dbi` 命令。一旦你放置了断点，使用 `dc` 命令开始运行二进制文件。你可以使用 `dbt` 命令查看堆栈，它可以显示函数调用。最后，你可以使用 `drr` 命令转储寄存器的内容：

1. `$ r2 -d -A ./adder`
2. `Process with PID 17453 started...`
3. `= attach 17453 17453`
4. `bin.baddr 0x00400000`
5. `Using 0x400000`
6. `asm.bits 64`
7. `[x] Analyze all flags starting with sym. and entry0 (aa)`
8. `[x] Analyze function calls (aac)`
9. `[x] Analyze len bytes of instructions for references (aar)`
10. `[x] Check for vtables`
11. `[x] Type matching analysis for all functions (aaft)`
12. `[x] Propagate noreturn information`
13. `[x] Use -AA or aaaa to perform additional experimental analysis.`
14.  `-- git checkout hamster`
15. `[0x7f77b0a28030]>`
16. `[0x7f77b0a28030]> db main`
17. `[0x7f77b0a28030]>`
18. `[0x7f77b0a28030]> db sym.adder`
19. `[0x7f77b0a28030]>`
20. `[0x7f77b0a28030]> dbi`
21. `0 0x004005a5 E:1 T:0`
22. `1 0x00400596 E:1 T:0`
23. `[0x7f77b0a28030]>`
24. `[0x7f77b0a28030]> afl | grep main`
25. `0x004005a5    1 55           main`
26. `[0x7f77b0a28030]>`
27. `[0x7f77b0a28030]> afl | grep sym.adder`
28. `0x00400596    1 15           sym.adder`
29. `[0x7f77b0a28030]>`
30. `[0x7f77b0a28030]> dc`
31. `hit breakpoint at: 0x4005a5`
32. `[0x004005a5]>`
33. `[0x004005a5]> dbt`
34. `0  0x4005a5           sp: 0x0                 0    [main]  main sym.adder+15`
35. `1  0x7f77b0687873     sp: 0x7ffe35ff6858      0    [??]  section..gnu.build.attributes-1345820597`
36. `2  0x7f77b0a36e0a     sp: 0x7ffe35ff68e8      144  [??]  map.usr_lib64_ld_2.28.so.r_x+65034`
37. `[0x004005a5]> dc`
38. `hit breakpoint at: 0x400596`
39. `[0x00400596]> dbt`
40. `0  0x400596           sp: 0x0                 0    [sym.adder]  rip entry.init0+6`
41. `1  0x4005be           sp: 0x7ffe35ff6838      0    [main]  main+25`
42. `2  0x7f77b0687873     sp: 0x7ffe35ff6858      32   [??]  section..gnu.build.attributes-1345820597`
43. `3  0x7f77b0a36e0a     sp: 0x7ffe35ff68e8      144  [??]  map.usr_lib64_ld_2.28.so.r_x+65034`
44. `[0x00400596]>`
45. `[0x00400596]>`
46. `[0x00400596]> dr`
47. `rax = 0x00000064`
48. `rbx = 0x00000000`
49. `rcx = 0x7f77b0a21738`
50. `rdx = 0x7ffe35ff6948`
51. `r8 = 0x7f77b0a22da0`
52. `r9 = 0x7f77b0a22da0`
53. `r10 = 0x0000000f`
54. `r11 = 0x00000002`
55. `r12 = 0x004004b0`
56. `r13 = 0x7ffe35ff6930`
57. `r14 = 0x00000000`
58. `r15 = 0x00000000`
59. `rsi = 0x7ffe35ff6938`
60. `rdi = 0x00000064`
61. `rsp = 0x7ffe35ff6838`
62. `rbp = 0x7ffe35ff6850`
63. `rip = 0x00400596`
64. `rflags = 0x00000202`
65. `orax = 0xffffffffffffffff`
66. `[0x00400596]>`

### 反编译器

能够理解汇编是二进制分析的前提。汇编语言总是与二进制建立和预期运行的架构相关。一行源代码和汇编代码之间从来没有 1:1 的映射。通常，一行 C 源代码会产生多行汇编代码。所以，逐行读取汇编代码并不是最佳的选择。

这就是反编译器的作用。它们试图根据汇编指令重建可能的源代码。这与用于创建二进制的源代码绝不完全相同，它是基于汇编的源代码的近似表示。另外，要考虑到编译器进行的优化，它会生成不同的汇编代码以加快速度，减小二进制的大小等，会使反编译器的工作更加困难。另外，恶意软件作者经常故意混淆代码，让恶意软件的分析人员望而却步。

Radare2 通过插件提供反编译器。你可以安装任何 Radare2 支持的反编译器。使用 `r2pm -l` 命令可以查看当前插件。使用 `r2pm install` 命令来安装一个示例的反编译器 `r2dec`：

1. `$ r2pm  -l`
2. `$`
3. `$ r2pm install r2dec`
4. `Cloning into 'r2dec'...`
5. `remote: Enumerating objects: 100, done.`
6. `remote: Counting objects: 100% (100/100), done.`
7. `remote: Compressing objects: 100% (97/97), done.`
8. `remote: Total 100 (delta 18), reused 27 (delta 1), pack-reused 0`
9. `Receiving objects: 100% (100/100), 1.01 MiB | 1.31 MiB/s, done.`
10. `Resolving deltas: 100% (18/18), done.`
11. `Install Done For r2dec`
12. `gmake: Entering directory '/root/.local/share/radare2/r2pm/git/r2dec/p'`
13. `[CC] duktape/duktape.o`
14. `[CC] duktape/duk_console.o`
15. `[CC] core_pdd.o`
16. `[CC] core_pdd.so`
17. `gmake: Leaving directory '/root/.local/share/radare2/r2pm/git/r2dec/p'`
18. `$`
19. `$ r2pm  -l`
20. `r2dec`
21. `$`

### 反编译器视图

要反编译一个二进制文件，在 `r2` 中加载二进制文件并自动分析它。在本例中，使用 `s sym.adder` 命令移动到感兴趣的 `adder` 函数，然后使用 `pdda` 命令并排查看汇编和反编译后的源代码。阅读这个反编译后的源代码往往比逐行阅读汇编更容易：

1. `$ r2 -A ./adder`
2. `[x] Analyze all flags starting with sym. and entry0 (aa)`
3. `[x] Analyze function calls (aac)`
4. `[x] Analyze len bytes of instructions for references (aar)`
5. `[x] Check for vtables`
6. `[x] Type matching analysis for all functions (aaft)`
7. `[x] Propagate noreturn information`
8. `[x] Use -AA or aaaa to perform additional experimental analysis.`
9.  `-- What do you want to debug today?`
10. `[0x004004b0]>`
11. `[0x004004b0]> s sym.adder`
12. `[0x00400596]>`
13. `[0x00400596]> s`
14. `0x400596`
15. `[0x00400596]>`
16. `[0x00400596]> pdda`
17.     `; assembly                               | /* r2dec pseudo code output */`
18.                                              `| /* ./adder @ 0x400596 */`
19.                                              `| #include &lt;stdint.h>`
20.                                              `|`  
21.     `; (fcn) sym.adder ()                     | int32_t adder (int64_t arg1) {`
22.                                              `|     int64_t var_4h;`
23.                                              `|     rdi = arg1;`
24.     `0x00400596 push rbp                      |`    
25.     `0x00400597 mov rbp, rsp                  |`    
26.     `0x0040059a mov dword [rbp - 4], edi      |     *((rbp - 4)) = edi;`
27.     `0x0040059d mov eax, dword [rbp - 4]      |     eax = *((rbp - 4));`
28.     `0x004005a0 add eax, 1                    |     eax++;`
29.     `0x004005a3 pop rbp                       |`    
30.     `0x004005a4 ret                           |     return eax;`
31.                                              `| }`
32. `[0x00400596]>`

### 配置设置

随着你对 Radare2 的使用越来越熟悉，你会想改变它的配置，以适应你的工作方式。你可以使用 `e` 命令查看 `r2` 的默认配置。要设置一个特定的配置，在 `e` 命令后面添加 `config = value`：

1. `[0x004005a5]> e | wc -l`
2. `593`
3. `[0x004005a5]> e | grep syntax`
4. `asm.syntax = intel`
5. `[0x004005a5]>`
6. `[0x004005a5]> e asm.syntax = att`
7. `[0x004005a5]>`
8. `[0x004005a5]> e | grep syntax`
9. `asm.syntax = att`
10. `[0x004005a5]>`

要使配置更改永久化，请将它们放在 `r2` 启动时读取的名为 `.radare2rc` 的启动文件中。这个文件通常在你的主目录下，如果没有，你可以创建一个。一些示例配置选项包括：

1. `$ cat ~/.radare2rc`
2. `e asm.syntax = att`
3. `e scr.utf8 = true`
4. `eco solarized`
5. `e cmd.stack = true`
6. `e stack.size = 256`
7. `$`

### 探索更多

你已经看到了足够多的 Radare2 功能，对这个工具有了一定的了解。因为 Radare2 遵循 Unix 哲学，即使你可以从它的主控台做各种事情，它也会在下面使用一套独立的二进制来完成它的任务。

探索下面列出的独立二进制文件，看看它们是如何工作的。例如，用 `iI` 命令在控制台看到的二进制信息也可以用 `rabin2 <binary>` 命令找到：

1. `$ cd bin/`
2. `$`
3. `$ ls`
4. `prefix  r2agent    r2pm  rabin2   radiff2  ragg2    rarun2   rasm2`
5. `r2      r2-indent  r2r   radare2  rafind2  rahash2  rasign2  rax2`
6. `$`

你觉得 Radare2 怎么样？请在评论中分享你的反馈。

---

via: [https://opensource.com/article/21/1/linux-radare2](https://opensource.com/article/21/1/linux-radare2)

作者：[Gaurav Kamathe](https://opensource.com/users/gkamathe) 选题：[lujun9972](https://github.com/lujun9972) 译者：[wxy](https://github.com/wxy) 校对：[wxy](https://github.com/wxy)

本文由 [LCTT](https://github.com/LCTT/TranslateProject) 原创编译，[Linux中国](https://linux.cn/article-13074-1.html) 荣誉推出

![](https://img.linux.net.cn/static/image/common/linisi.svg)  

  

### 最新评论

> [1]
> 
> 来自四川成都的 Chrome 94.0|Windows 10 用户 发表于 2021-11-30 16:32 的评论：
> 
> [8 赞](https://linux.cn/portal.php?mod=review&action=postreview&do=support&idtype=aid&tid=13074&pid=50110&hash=0dbe63c4) [回复](https://linux.cn/portal.php?mod=portalcp&ac=comment&op=reply&cid=50110&aid=13074&idtype=)
> 
> 你好，请教一下 ii 命令显示二进制所有导入的库，那个lib字段为啥全是空的？有什么办法把lib字段显示出来吗？

来自河北承德的 Firefox 109.0|Windows 10 用户 2023-02-07 21:29 [3 赞](https://linux.cn/portal.php?mod=review&action=postreview&do=support&idtype=aid&tid=13074&pid=52511&hash=0dbe63c4) [回复](https://linux.cn/portal.php?mod=portalcp&ac=comment&op=reply&cid=52511&aid=13074&idtype=)

ret2libc

[phoenix_wangxd [Chrome 88.0|Mac 11.1]](https://linux.cn/space/58476/) 2021-02-02 23:19 [45 赞](https://linux.cn/portal.php?mod=review&action=postreview&do=support&idtype=aid&tid=13074&pid=49107&hash=0dbe63c4) [回复](https://linux.cn/portal.php?mod=portalcp&ac=comment&op=reply&cid=49107&aid=13074&idtype=)

十分感谢，介绍的很详细。 Radare2，分析二进制的工具。有时间的话，研究一下

译自：[opensource.com](https://opensource.com/article/21/1/linux-radare2) 作者： Gaurav Kamathe  
原创：[LCTT](https://linux.cn/lctt/) [https://linux.cn/article-13074-1.html](https://linux.cn/article-13074-1.html) 译者： Xingyu.Wang  
  
本文由 LCTT 原创翻译，[Linux 中国首发](https://linux.cn/article-13074-1.html)。也想加入译者行列，为开源做一些自己的贡献么？欢迎加入 [LCTT](https://linux.cn/lctt/)！  
翻译工作和译文发表仅用于学习和交流目的，翻译工作遵照 [CC-BY-SA 协议规定](https://creativecommons.org/licenses/by-sa/4.0/deed.zh)，如果我们的工作有侵犯到您的权益，请及时联系我们。  
欢迎遵照 [CC-BY-SA 协议规定](https://creativecommons.org/licenses/by-sa/4.0/deed.zh) 转载，敬请在正文中标注并保留原文/译文链接和作者/译者等信息。  
文章仅代表作者的知识和看法，如有不同观点，请楼下排队吐槽 :D  

[](https://linux.cn/home.php?mod=spacecp&ac=favorite&type=article&id=13074&handlekey=favoritearticlehk_13074 "收藏")[](https://linux.cn/article-13074-1.html?pr "打印")

_上一篇：[3 个自动化电子邮件过滤器的技巧](https://linux.cn/article-13073-1.html)__下一篇：[使用 Ansible 的第一天](https://linux.cn/article-13079-1.html)_

LCTT 译者

[![](https://avatars.githubusercontent.com/u/128338?v=4)](https://linux.cn/lctt/wxy)

[![](https://img.linux.net.cn/static/image/common/github_icon.png)](https://github.com/wxy) [Xingyu.Wang](https://linux.cn/lctt/wxy) 💎💎💎

共计翻译： 995.0 篇 | 共计贡献： 3546 天

贡献时间：2014-07-25 -> 2024-04-09

[访问我的 LCTT 主页](https://linux.cn/lctt/wxy) | [在 GitHub 上关注我](https://github.com/wxy)

  

### 相关阅读

- [二进制分享](https://linux.cn/tag-%E4%BA%8C%E8%BF%9B%E5%88%B6%E5%88%86%E4%BA%AB.html)
- [更多标签](https://linux.cn/tag/)

  

Linux 中国 © 2003 - 2024

[京ICP备2021020457号-1](https://beian.miit.gov.cn/) 京公网安备110105001595

[服务条款](https://linux.cn/legal.html) | 除特别申明外，本站原创内容版权遵循 [CC-BY-SA 协议规定](https://creativecommons.org/licenses/by-sa/4.0/deed.zh)

[](https://linux.cn/home.php?mod=spacecp&ac=favorite&type=article&id=13074&handlekey=favoritearticlehk_13074 "收藏")[](https://linux.cn/article-13074-1.html?pr "!print!")
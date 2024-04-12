##### 基本分析
1. exeinfo 查看![[Pasted image 20240406201857.png]]32 位 C++ 程序，没有加壳
2.  直接拖进 IDA 查看![[Pasted image 20240406202026.png]]非常简单，只有一个 `Can you find me?` 字符串作为提示信息
3. 进入 `___main` 函数![[Pasted image 20240406202156.png]]只有初始化信息
4. 猜测 flag 藏在左侧函数列表中且没被调用。此时发现 `_main` 上面的 `_ques` 函数非常可疑（看上去就不像是自带的函数），进入查看![[Pasted image 20240406202358.png]]发现有 `putchar` 函数，且会输出 `*` 和空格，基本可以确定是关键函数，接下来需要考虑如何处理
5. 主要有两种方法。第一种方法是直接根据函数的伪代码编写脚本，第二种方法是让程序自己调用这个函数。这里使用第二种方法，并分别使用 IDA Pro 和 x64dbg 两种方式实现
##### IDA Pro 实现
1. `_main` 函数里直接调用了 `___main` 函数![[Pasted image 20240406203733.png]]可以通过将此处调用的 `___main` 函数更改为 `_ques` 来实现让程序自己调用该函数
2. 进入 IDA 的反汇编窗口![[Pasted image 20240406204006.png]]在 `_main` 函数中找到 `call ___main` 命令，右键选择 `Assemble`
3. 将 `call ___main` 命令更改为 `cal _ques`![[Pasted image 20240406204108.png]]![[Pasted image 20240406204113.png]]
4. 然后再右击选择 `Apply patches`![[Pasted image 20240406204425.png]]
5. 用 IDA 动态调试，选择 `Local Windows debugger`，得到结果![[Pasted image 20240406204534.png]]
6. 结果验证正确![[Pasted image 20240406203440.png]]
##### x64dbg 实现
1. 直接拖进 x32dbg，在程序运行时更改 eip 的值使其指向 `_ques` 函数以实现调用![[Pasted image 20240406204811.png]]
2. 可以根据 `Can you find me?` 这个提示信息快速定位 `_main` 函数所在。`F9` 运行后在x64dbg 中使用搜索字符串功能可以直接发现字符串 ![[Pasted image 20240406205907.png]]
4. 双击进入![[Pasted image 20240406210037.png]]可以非常明显地发现此处的 `attachment.4021A0` 为自定义函数，可以结合 IDA 内的静态代码，发现此处为调用 `_main` 函数的代码，即只需在此处下断点，在程序运行到此处时更改 esp 指向即可调用 `_ques` 函数
5. IDA 中 `_ques` 函数在 `_main` 函数的上方，所以此处向上找一下，可以很快找到 `putchar` 函数的调用，且输出为 `*` 和空格，确定为 `_ques` 函数![[Pasted image 20240406211017.png]]该函数的位置即为程序运行到断点处时需要更改为的值![[Pasted image 20240406211122.png]]
6. `F9` 运行直到断点处![[Pasted image 20240406211454.png]]
7. `F7` 步入![[Pasted image 20240406211517.png]]
8. 将此处的 esp 更改为 `00401520`，即为 `_ques` 函数所在位置![[Pasted image 20240406211614.png]]
9. `F9` 直接运行到结束![[Pasted image 20240406211640.png]]
10. 结果验证正确![[Pasted image 20240406203440.png]]
想要执行的行为本身就有函数在二进制文件中，则可以直接用 ROP 放好参数直接使用，而不用 ROP 去堆全部的行为
在 PIE 关闭的情况下，即使不知道 library function address （因为 ASLR），也可以通过 `return` 到 `.plt` 上来使用这个函数，此做法称为 `ret2plt`

所谓的一步到达 `OEP` 的脱壳方法, 是根据所脱壳的特征, 寻找其距离 `OEP` 最近的一处汇编指令, 然后下 `int3` 断点, 在程序走到 `OEP` 的时候 `dump` 程序.

如一些压缩壳往往 `popad` 指令距离 `OEP` 或者大 `jmp` 特别近, 因此使用 x64dbg 的搜索功能, 可以搜索壳的特征汇编代码, 达到一步断点到达 `OEP` 的效果.

>注：仅适用于极少数压缩壳

## 要点

1. 查找 `popad` 命令
2. `Ctrl+l` 跳转到下一个匹配处
3. 找到匹配处, 确认是壳解压完毕即将跳转到 OEP 部分, 则设下断点运行到该处
4. 只适用于极少数压缩壳

## 例题: BUUCTF 新年快乐

1. 查壳，发现 UPX 壳

![](https://gitee.com/chpocenkey/images/raw/master/20240731213217.png)

2. 使用 x64dbg 打开

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731213432.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731213457.png)

3. 鼠标右键，选择 `搜索 -> 所有模块 -> 命令` ，输入 `popad`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731225824.png)

4. 选择最上面的

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731225848.png)

5. 使用 `Ctrl+l` 快捷键快捷查找，主要寻找在 `popad` 后跟着 `jmp` 命令的（就几条命令的距离）

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731230331.png)

6. 在此处设置硬件断点，直接运行，程序会自动停止

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731230650.png)

7. 使用 Scylla dump 出脱壳后的程序

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731230800.png)

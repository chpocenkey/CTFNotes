## 简介

ESP 定律又称堆栈平衡定律，是应用频率最高的脱壳方法之一

## 原理

ESP 定律的原理在于利用程序中堆栈平衡来快速找到 OEP

由于在程序自解密或者自解压过程中, 不少壳会先将当前寄存器状态压栈, 如使用`pushad`, 在解压结束后, 会将之前的寄存器值出栈, 如使用`popad`. 因此在寄存器出栈时, 往往程序代码被恢复, 此时硬件断点触发. 然后在程序当前位置, 只需要少许单步操作, 就很容易到达正确的 OEP 位置.
## 要点

1. 程序刚载入开始 pushad/pushfd
2. 将全部寄存器压栈后就设对 ESP 寄存器设硬件断点
3. 运行程序, 触发断点
4. 删除硬件断点开始分析

## 例题: BUUCTF 新年快乐

1. 查壳，发现 UPX 壳

![](https://gitee.com/chpocenkey/images/raw/master/20240731213217.png)

2. 使用 x64dbg 打开

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731213432.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731213457.png)

3. 因为入口不是 `pushad` ，所以在 `断点` 窗口查看并跳转到 `pushad` 断点

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222357.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222412.png)

4. 在此处 （ `pushad` 的位置 ），设置 `EIP`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222553.png)

6. 注意此时的 `ESP` 值，使用 `F8` 单步步过直到 `ESP` 的值发生变化（颜色会由黑色变为红色）

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222630.png)

7. 鼠标指向 `ESP` 处右键，选择 `在内存窗口中转到`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222724.png)

8. 在内存窗口转到的位置右键鼠标，选择 `断点 -> 硬件访问 -> 4 字节`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731222828.png)

9. 直接运行，程序自动停下来，找到下方的一个 `jmp` 指令所要跳转的位置就是程序的 `OEP`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731224021.png)

10. 使用 Scylla，在 `OEP` 处填入程序的 `OEP` （此处为 `401280` ）

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731224223.png)

11. 点击 `Dump` 保存 `dump` 文件

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731224313.png)


12. 先后点击 `IAT Autosearch` 和 `Get Imports` ，再点击 `Fix Dump` ，选择之前的 `dump` 文件（有 `_dump` 后缀），得到 `_dump_SCY` 后缀的文件，即为脱壳后的文件

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240731224504.png)

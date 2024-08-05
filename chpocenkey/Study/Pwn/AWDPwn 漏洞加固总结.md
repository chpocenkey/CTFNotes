## AWD简介

AWD(Attack With Defense，攻防兼备) 模式需要在一场比赛里要扮演攻击方和防守方，利用漏洞攻击其他队伍进行得分，修复漏洞可以避免被其他队伍攻击而失分。也就是说，攻击别人的靶机可以获取 Flag 分数时，别人会被扣分，同时也要保护自己的主机不被别人攻陷而扣分。

## Patch-PWN

各家 awd 平台检查机制各不相同，原则上是只针对漏洞点进行 patch 加固，也就是最小修改加固。以下总结不需要改动文件大小、针对漏洞点进行 patch 的几种漏洞类型。

### Patch资料

跳转指令

无符号跳转

|汇编指令|描述|
|---|---|
|JA|无符号大于则跳转|
|JNA|无符号不大于则跳转|
|JAE|无符号大于等于则跳转（同JNB）|
|JNAE|无符号不大于等于则跳转（同JB）|
|JB|无符号小于则跳转|
|JNB|无符号不小于则跳转|
|JBE|无符号小于等于则跳转（同JNA）|
|JBNE|无符号不小于等于则跳转（同JA）|

有符号跳转

|汇编指令|描述|
|---|---|
|JG|有符号大于则跳转|
|JNG|有符号不大于则跳转|
|JGE|有符号大于等于则跳转（同JNL）|
|JNGE|有符号不大于等于则跳转（同JL）|
|JL|有符号小于则跳转|
|JNL|有符号不小于则跳转|
|JLE|有符号小于等于则跳转（同JNG）|
|JNLE|有符号不小于等于则跳转（同JG）|

### Patch-整数溢出
![image-20210710154128227](https://image.3001.net/images/20210802/1627874511_610764cfda5f7d52d4d4b.png!small)

Scanf 以 long int 长整形读取输入到 unsigned int 变量 v2 中，然后将 v2 强制转为 int 再与int 48 比较。

但从 scanf 读入一个负数时，最高位为 1 ，从 unsigned int 强制转换为 int 结果是负数，必定比 48 小，在后面 read 读入会造成栈溢出。

Patch方法

将第 9 行的 if 跳转汇编指令 patch 为无符号的跳转指令，具体指令参考[跳转指令](http://www.heetian.com/backend/core/info/view.do?id=1037&queryNodeId=122&queryNodeType=0&queryInfoPermType=&queryStatus=&position=0&#%20%E8%B7%B3%E8%BD%AC%E6%8C%87%E4%BB%A4)。

**使用 keypatach 进行修改**：

jle --> jbe

![image-20210710155953262](https://image.3001.net/images/20210802/1627874513_610764d15feaaa3c0bf34.png!small)

![image-20210710160006943](https://image.3001.net/images/20210802/1627874514_610764d28fd3b84c0abb9.png!small)

### Patch-栈溢出

> 对于栈溢出加固，x64 更容易一些，因为是使用寄存器传参，而x86 使用栈传参，需要用 nop 等保持加固前后的空间不变。

x64

![image-20210715165543609](https://image.3001.net/images/20210802/1627874515_610764d3bbb993dd6fb40.png!small)

Patch方法

100 是第三个参数，存储寄存器是 rdx ，找到给 rdx 传参的汇编指令进行 patch

使用 ida 默认修改插件修改（Edit-Patch Program-Change word），也可以用 keypatach ：

> 0x64 是长度
> 
> 0xBA 是操作符

![image-20210710183002548](https://image.3001.net/images/20210802/1627874517_610764d5bf6df6bbc05e2.png!small)

0x64 --> 0x20

![image-20210710183212767](https://image.3001.net/images/20210802/1627874519_610764d745f0ab24d2ea9.png!small)

x86

不需要对齐

![image-20210711004750198](https://image.3001.net/images/20210802/1627874520_610764d833931532de9e8.png!small)

找到压栈的指令，修改压入的数值

修改数值需要补上`0x`

这里修改前 size 为 2 ，修改后 size 也为 2 ，所以这题 patch 不需要用 nop 保持 size

需要对齐

![image-20210711180331314](https://image.3001.net/images/20210802/1627874521_610764d935ee6121746d3.png!small)

找到压栈的指令，修改压入的数值

直接修改 0x20 后，size 长度不对齐，会引起栈空间变化，需要用`nop`进行对齐：

**更方便快捷方法是勾选`NOPs padding until next instruction boundary`进行自动填充。**

### Patch-格式化字符串

![image-20210711234054628](https://image.3001.net/images/20210802/1627874523_610764db87d4565a4735f.png!small)

修改函数

将 printf 改为 puts ，将 call 的地址改为 puts plt 地址：

![image-20210711234209674](https://image.3001.net/images/20210802/1627874526_610764de19c0648d63cc7.png!small)

**这个方法局限性在于：puts 会在原字符串多加`\n`，主办方 check 可能会因此而不通过**

修改printf参数

将`printf(format)`修改为`printf("%s",format)`

修改 printf 前面的传参指令：

![image-20210712000236624](https://image.3001.net/images/20210802/1627874527_610764dfedefa3aab9a56.png!small)

mov edi, offset 0x400c01;  
mov esi,offset format;

![image-20210712000422524](https://image.3001.net/images/20210802/1627874529_610764e17fe0856685c0c.png!small)

### Patch-UAF

![image-20210713134230716](https://image.3001.net/images/20210802/1627874530_610764e2d40fbf28b23ab.png!small)

修改逻辑是劫持 call 指令跳转到 .eh_frame 段上写入的自定义汇编程序。

先在 .eh_frame 段上写入代码，首先是`call free`完成释放，然后对 chunk_list 进行置零。取 chunk_list 地址的汇编可以从 call free 前面抄过来：

```
call 0x900;           #调用free函数（plt地址）  
  
mov     eax, [rbp-0xc]; #取出下标值  
cdqe;  
lea     rdx, ds:0[rax*8];  
lea rax, qword ptr [heap];  
  
mov r8,0; #段地址不能直接赋予立即数  
mov [rdx+rax],r8;  
jmp 0xD56; #跳回原来的地址
```
![image-20210713134459423](https://image.3001.net/images/20210802/1627874532_610764e490314c808b89b.png!small)

### Patch-if范围

假设需要将图上第二个 if 放到 if 结构内，修改跳转的地址即可：

![image-20210719113705210](https://image.3001.net/images/20210802/1627874534_610764e65d9ae7ad6d4df.png!small)

原始跳转代码：

![image-20210719114103511](https://image.3001.net/images/20210802/1627874537_610764e991e4138902042.png!small)

js 0x40081C --> js 0x400845

![image-20210719114649963](https://image.3001.net/images/20210802/1627874541_610764edd07ffbc9a5b93.png!small)

### Patch-更换危险函数

类似与 uaf 一样写汇编实现功能调用，将危险函数替换为其他函数，如果程序中没有目标函数，就通过系统调用方式调用。

将 gets 替换为 read 输入

![image-20210720042111225](https://image.3001.net/images/20210802/1627874543_610764ef268f5878fa636.png!small)

.eh_frame 写入汇编，将 rdi 的写入地址移动到 rsi ，把其他寄存器也传参之后进行系统调用：

![image-20210720042440884](https://image.3001.net/images/20210802/1627874546_610764f210749ffa2b758.png!small)

![image-20210720042425944](https://image.3001.net/images/20210802/1627874549_610764f59ae92a3b4d40b.png!small)

![image-20210720042503413](https://image.3001.net/images/20210802/1627874553_610764f91c9645cc600c5.png!small)
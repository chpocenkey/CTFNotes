## 简介

SMC（Self Modifying Code）自修改代码，指通过修改代码或数据，阻止别人直接静态分析，然后再动态运行程序时堆代码进行解密，从而达到程序正常运行的效果

SMC 的实现有多种方式

- 修改 PE 文件的头
- 使用 API Hook 实现代码加密和解密
- 使用 VMProtect 等第三方加密工具
- ...

## 识别

SMC 的实现需要对目标内存进行修改，但是 `.text` 段一般是没有写权限的，所以就需要拥有修改目标内存的权限

- 在 Linux 系统中，可以通过 `mprotect` 函数修改目标内存的权限
- 在 Windows 系统中，可以通过 `VirtualProtect` 函数修改目标内存的权限

同样可以观察是否有这两个函数来判断是否进行了 SMC

## 破解

SMC 一般有两种破解方法

- 找到对代码或数据加密的函数后通过 idapython 写解密脚本
- 动态调试到 SMC 解密结束的地方将内存 dump 出来

## 例题：SCUx401CTF2021 RE2-pixpix

1. 查壳，32 位，无壳

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240801213623.png)


2. 使用 IDA Pro 打开

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240801213536.png)


3. 发现两个 `VirtualProtect` 函数，该函数用于修改目标内存的权限，基本可以判定存在 SMC ，即自修改代码，对伪代码进行基本的分析

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HDC DC; // eax
  COLORREF Pixel; // eax
  unsigned int v5; // edi
  unsigned int v6; // kr00_4
  unsigned int v7; // esi
  int v9; // [esp+0h] [ebp-Ch]
  DWORD flOldProtect; // [esp+8h] [ebp-4h] BYREF

  DC = GetDC(0);
  Pixel = GetPixel(DC, 401, 401);
  word_9A3384 = Pixel;
  byte_9A3386 = BYTE2(Pixel);
  VirtualProtect(sub_9A1050, (char *)nullsub_1 - (char *)sub_9A1050, 0x40u, &flOldProtect);
  v5 = 0;
  if ( (char *)nullsub_1 != (char *)sub_9A1050 )
  {
    do
    {
      v6 = v5;
      v7 = v5++;
      *((_BYTE *)sub_9A1050 + v7) ^= *((_BYTE *)&word_9A3384 + v6 % 3);
    }
    while ( v5 < (char *)nullsub_1 - (char *)sub_9A1050 );
  }
  VirtualProtect(sub_9A1050, (char *)nullsub_1 - (char *)sub_9A1050, flOldProtect, &flOldProtect);
  sub_9A1050(v9);
  return 0;
}
```

4. 发现 `nullsub_1` 的地址为 `0x009A10B0` ，所以解密的范围 `0x009A1050 ~ 0x009A10B0`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240801214035.png)

5. 继续观察，发现函数的加密只是一个简单的异或，唯一的问题在于 `word_9A3384` 的数据不知道，而函数的加密是和这个数组的前三个数据相异或，所以需要找到这三个数据的具体值

```
  VirtualProtect(sub_9A1050, (char *)nullsub_1 - (char *)sub_9A1050, 0x40u, &flOldProtect);
  v5 = 0;
  if ( (char *)nullsub_1 != (char *)sub_9A1050 )
  {
    do
    {
      v6 = v5;
      v7 = v5++;
      *((_BYTE *)sub_9A1050 + v7) ^= *((_BYTE *)&word_9A3384 + v6 % 3);
    }
    while ( v5 < (char *)nullsub_1 - (char *)sub_9A1050 );
  }
  VirtualProtect(sub_9A1050, (char *)nullsub_1 - (char *)sub_9A1050, flOldProtect, &flOldProtect);
```

6. 选择 `Options -> General` ，将 `Number of opcode bytes` 修改为 5，用于显示机器码

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802075832.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802075904.png)

7. 因为 C 语言生成的 x86 exe 文件，其各函数头是固定的，目的是处理栈帧，所以观察 `main` 函数的开头三个机器码为 `55` , `8B` , `EC` ，要修改的函数 `sub_9A1050` 的开头三个机器码为 `61` , `BB` , `DD` ，所以可以得到异或的三个值分别为 `0x34, 0x30, 0x31`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802080231.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802080240.png)

8. 已经得到相关数据以及解密方法，编写 IDAPython 脚本解密

```python
import idc
st_addr = 0x9a1050
ed_addr = 0x9a10b0
pix = [0x34, 0x30, 0x31]
for i in range(st_addr, ed_addr):
    b = get_bytes(i, 1)
    idc.patch_byte(i, ord(b) ^ pix[(i - st_addr) % 3])
```

9. 使用 `Shift + F2` 直接将脚本复制上去，或者用 `Alt + F7` 将编写好的脚本运行

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802080845.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802080835.png)

10. 可以看到 `sub_9A1050` 函数的汇编已经发生改变

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802080934.png)

11. 将所有 `db ` 命令使用快捷键 `c` 强制转换为汇编，再使用 `F5` 反编译就能得到最终的函数

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240802081116.png)

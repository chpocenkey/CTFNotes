Base 算法是逆向中很常见，也是很简单的算法，基本上是新手逆向必备

Base 家族的编码方式提供了一种方法，将原始的二进制数据转换成一个更友好的、由特定字符集组成的字符串格式

这里给出一些常见 Base 的字符集和对应说明

| 编码        | 字符集                                                                                      | 备注           |
| --------- | ---------------------------------------------------------------------------------------- | ------------ |
| Base2     | `01`                                                                                     | 二进制          |
| Base16    | `0123456789ABCDEF (或0123456789abcdef)`                                                   | 十六进制         |
| Base32    | `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`                                                       |              |
| Base32Hex | `0123456789ABCDEFGHIJKLMNOPQRSTUV`                                                       | Base32 的变体   |
| Base58    | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`                             | 主要用于比特币地址    |
| Base64    | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`                       |              |
| Base64URL | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`                       | 适用于 URL 和文件名 |
| Base85    | `!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstu` |              |

## Base16
### 概念

Base16 编码，也被称为十六进制编码，是一种将二进制数据转换为文本表示的编码方式，它使用 16 个字符中的一个来表示二进制数值中的 4 个二进制位
### 字符集

Base16 字符集由 0 ~ 9 和 A ~ F 共十六个字符组成

Base16 的替换表定义为字符串数组为

```
0123456789ABCDEF
```
### 编码原理

1. 获取字符在其所属编码系统中的 8 位二进制表示
2. 将二进制数每 4 位为一组进行拆分
3. 将拆分的每组 4 个二进制位转化为十进制数
4. 与 Base16 替换表进行对比替换
### 示例

例如，将字符串 `xyz` 进行 base16 加密

`x` 的 ASCII 码为 `0x78` ，二进制表示为 `0111 1000`
`y` 的 ASCII 码为 `0x79` ，二进制表示为 `0111 1001`
`z` 的 ASCII 码为 `0x7A` ，二进制表示为 `0111 1010`

将这 3 个 8 位字符转化为 6 个 4 位的二进制数即为

```
0111 1000 | 0111 1001 | 0111 1010
0111 | 1000 | 0111 | 1001 | 0111 | 1010
```

接着将二进制数转为十进制

```
0111 1000 | 0111 1001 | 0111 1010
0111 | 1000 | 0111 | 1001 | 0111 | 1010
7    | 8    | 7    | 9    | 7    | A
```

查 Base16 表得到最终结果

```
0111 1000 | 0111 1001 | 0111 1010
0111 | 1000 | 0111 | 1001 | 0111 | 1010
7    | 8    | 7    | 9    | 7    | A
78797A
```
### 代码实现

```C
#include "base16.h"
  
// 用于Base16编码的字符集
const unsigned char *base16_table = "0123456789ABCDEF";
  
// Base16编码函数
unsigned char *base16_encode(const unsigned char *str)
{
    unsigned char *res;
    long len = strlen(str);
    res = malloc(sizeof(unsigned char) * len * 2 + 1);
  
    for (int i = 0; i < len; ++i)
    {
        res[i * 2] = base16_table[(str[i] >> 4) & 0x0F];
        res[i * 2 + 1] = base16_table[str[i] & 0x0F];
    }
  
    res[len * 2] = '\0'; // 确保输出字符串以空字符结尾
  
    return res;
}
  
// Base16解码函数
unsigned char *base16_decode(const unsigned char *str)
{
    unsigned char *res;
    long len = strlen(str);
  
    res = malloc(sizeof(unsigned char) * len / 2 + 1);
  
    for (int i = 0; i < len; i += 2)
    {
        // 检查输入是否有效
        if (str[i] >= '0' && str[i] <= '9')
        {
            res[i / 2] = (str[i] - '0') << 4;
        }
        else if (str[i] >= 'A' && str[i] <= 'F')
        {
            res[i / 2] = (str[i] - 'A' + 10) << 4;
        }
        else
        {
            return 0; // 无效的字符，解码失败
        }
  
        if (str[i + 1] >= '0' && str[i + 1] <= '9')
        {
            res[i / 2] |= str[i + 1] - '0';
        }
        else if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
        {
            res[i / 2] |= str[i + 1] - 'A' + 10;
        }
        else
        {
            return 0; // 无效的字符，解码失败
        }
    }
    return res; // 返回解码后的数据长度
}
```

## Base32
### 概念

Base32 编码使用 32 个 ASCII 字符对任何数据进行编码
### 字符集

Base32 编码使用 32 个可打印字符（字母 A-Z 和数字 2-7 ）

Base32 通用的字典定义如下：

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
```

Base32 还提供了另外一种字典定义，即 Base32 十六进制字母表

>Base32 十六进制字母表是参照十六进制的计数规则定义的

```
0123456789ABCDEFGHIJKLMNOPQRSTUV
```
### 编码原理

1. 获取字符在其所属编码系统中的 8 位二进制表示
2. 将二进制数每 5 位为一组进行拆分
3. 将拆分的每组 5 个二进制位转化为十进制数，若最后一组长度不是 5 的倍数，需要在末位补 0
4. 与 Base32 替换表进行对比替换

>Base32 可以在末位补 `=` ，其作用在于方便一些程序的标准化运行，但是大多数情况下不添加也无关紧要。补 `=` 的规则为补充到 8 的倍数
### 示例

例如，将字符串 `xyz` 进行 base32 加密

`x` 的 ASCII 码为 `0x78` ，二进制表示为 `0111 1000`
`y` 的 ASCII 码为 `0x79` ，二进制表示为 `0111 1001`
`z` 的 ASCII 码为 `0x7A` ，二进制表示为 `0111 1010`

将这 3 个 8 位字符转化为 5 个 5 位的二进制数，末尾补 0 可得

```
0111 1000 | 0111 1001 | 0111 1010
01111 | 00001 | 11100 | 10111 | 10100
```

接着将二进制数转为十进制

```
0111 1000 | 0111 1001 | 0111 1010
01111 | 00001 | 11100 | 10111 | 10100
P     | B     | 4     | X     | U     
```

查 Base16 表得到最终结果

```
0111 1000 | 0111 1001 | 0111 1010
0111 | 1000 | 0111 | 1001 | 0111 | 1010
7    | 8    | 7    | 9    | 7    | A
78797A
```
### 代码实现

```C
#include "base32.h"
  
#ifndef CEIL_POS
#define CEIL_POS(X) (X > (uint64_t)(X) ? (uint64_t)(X + 1) : (uint64_t)(X))
#endif
  
unsigned char *base32_encode(const unsigned char *str)
{
    uint64_t len = strlen(str);
    uint64_t length = (len * 8 + 4) / 5 * 5;
    unsigned char *res = (unsigned char *)malloc(sizeof(unsigned char) * length);
    uint64_t idx = 0;
  
    for (uint64_t i = 0; i < len; i += 5)
    {
        uint64_t byte1 = (uint8_t)str[i];
        uint64_t byte2 = (i + 1 < len) ? (uint8_t)str[i + 1] : 0;
        uint32_t byte3 = (i + 2 < len) ? (uint8_t)str[i + 2] : 0;
        uint16_t byte4 = (i + 3 < len) ? (uint8_t)str[i + 3] : 0;
        uint8_t byte5 = (i + 4 < len) ? (uint8_t)str[i + 4] : 0;
  
        uint64_t quintuple = (byte1 << 32) | (byte2 << 24) | (byte3 << 16) | (byte4 << 8) | byte5;
  
        for (uint64_t j = 0; (j < 8) && (i + j * 0.625 < len); j++)
        {
            res[idx] = BASE32_TABLE[(quintuple >> (5 * (7 - j))) & 0x1f];
            idx++;
        }
    }
  
    char paddingChar = BASE32_TABLE[32];
    if (paddingChar)
    {
        while (idx % 8)
        {
            res[idx] = paddingChar;
            idx++;
        }
    }
    res[idx] = 0;
    return res;
}
  
unsigned char *base32_decode(const unsigned char *str)
{
    uint64_t len = strlen(str);
    while (str[len - 1] == BASE32_TABLE[32])
    {
        len--;
    }
    uint64_t length = CEIL_POS(len * 5 / 8) + 1;
    char *res = (unsigned char *)malloc(sizeof(unsigned char) * length);
    uint64_t idx = 0;
  
    for (uint64_t i = 0; i < len; i += 8)
    {
        uint64_t quintuple = 0;
        for (uint8_t j = 0; j < 8; ++j)
        {
            if (i + j < len)
                quintuple = (quintuple << 5) | ((uint8_t)BASE32_REVERSE_TABLE[str[i + j]] & 0x1f);
            else
                quintuple = quintuple << 5;
        }
        for (uint8_t j = 0; (j < 5); ++j)
        {
            res[idx] = (quintuple >> (8 * (4 - j))) & 0xff;
            idx++;
        }
    }
    res[idx] = 0;
    return res;
}
```
## Base58
### 概念

Base58 是在比特币中使用的一种独特的编码方式，主要用于产生比特币的钱包地址

base58 其实就是 base64 的变形，base58 的检索表比 base64 的检索表少了数字 `0` ，大写字母 `O` ，大写字母 `I` ，和小写字母 `l` ，以及 `+` 和 `/` 符号

base58 无法用整字节来转换表示 base58，所以开销会比base64 和 base16 大得多，但是有利于展示地址
### 字符集

base58 的替换表定义为字符串数组为

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```
### 编码原理

由于不再是 64 位，所以不再使用原来三变四的加密方式，而是使用了新的加密方式：

将密文与 58 进行辗转相除，直到商为 0，根据得到的模按照倒序查表得到 base58 编码
### 示例

例如，将字符串 `xyz` 进行 base58 加密

`x` 的 ASCII 码为 `0x78` ，二进制表示为 `0111 1000`
`y` 的 ASCII 码为 `0x79` ，二进制表示为 `0111 1001`
`z` 的 ASCII 码为 `0x7A` ，二进制表示为 `0111 1010`

将这 3 个 8 位字符转换为 1 个 24 位的二进制数即为

```
0111 1000 | 0111 1001 | 0111 1010
0111 1000 0111 1001 0111 1010
```

接着将二进制数转为十进制

```
0111 1000 | 0111 1001 | 0111 1010
0111 1000 0111 1001 0111 1010
7895418
```

将得到的十进制与 58 进行辗转相除

$$
\begin{align}
\frac{7895418}{58} &= 136127 \cdots\cdots 52 \\
\frac{136127}{58} &= 2347 \cdots\cdots 1 \\
\frac{2347}{58} &= 40 \cdots\cdots 27 \\
\frac{40}{58} &= 0 \cdots\cdots 40 \\
\end{align}
$$

查 Base58 表得到最终结果

```
40 | 27 | 1 | 52
hU2u
```

### 代码实现

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
  
unsigned char *base58_encode(unsigned char *str)  // 编码
{
  // 定义 base58 编码表
    static char *nb58 = (char *)"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t len = strlen((char *)str);
    size_t rlen = (len / 2 + 1) * 3;
    unsigned char *ret = (unsigned char *)malloc(rlen + len);
    unsigned char *src = ret + rlen;
    unsigned char *rptr = ret + rlen;
    unsigned char *ptr, *e = src + len - 1;
    size_t i;
    memcpy(src, str, len);
    while (src <= e) {
        if (*src) {
        unsigned char rest = 0;
        ptr = src;
        while (ptr <= e) {
            unsigned int c = rest * 256;
            rest = (c + *ptr) % 58;
            *ptr = (c + *ptr) / 58;
            ptr++;
        }
        --rptr;
        *rptr = nb58[rest];
        } else {
        src++;
        }
    }
    for (i = 0; i < ret + rlen - rptr; i++) ret[i] = rptr[i];
    ret[i] = 0;
    return ret;
}
  
unsigned char *base58_decode(unsigned char *src)  // 解码
{
    static char b58n[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,
        5,  6,  7,  8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15,
        16, -1, 17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
        -1, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1,
    };
    size_t len = strlen((char *)src);
    size_t rlen = (len / 4 + 1) * 3;
    unsigned char *ret = (unsigned char *)malloc(rlen);
    unsigned char *rptr = ret + rlen;
    size_t i;
    unsigned char *ptr;
    for (i = 0; i < len; i++) {
        char rest = b58n[src[i]];
        if (rest < 0) {
            free(ret);
            return NULL;
        }
        for (ptr = ret + rlen - 1; ptr >= rptr; ptr--) {
            unsigned int c = rest + *ptr * 58;
            *ptr = c % 256;
            rest = c / 256;
        }
        if (rest > 0) {
            rptr--;
            if (rptr < ret) {
                free(ret);
                return NULL;
            }
            *rptr = rest;
        }
    }
    for (i = 0; i < ret + rlen - rptr; i++) ret[i] = rptr[i];
    ret[i] = 0;
    return ret;
}
```
## Base64
### 概念

Base64 将 3 个 8 位字符转化为 4 个 6 位的二进制数（不足 8 位，高位补 0），通过查表来转化为字符

Base64常用于在通常处理文本[数据](https://zh.wikipedia.org/wiki/%E6%95%B0%E6%8D%AE "数据")的场合，表示、传输、存储一些二进制数据，包括[MIME](https://zh.wikipedia.org/wiki/MIME "MIME")的[电子邮件](https://zh.wikipedia.org/wiki/%E7%94%B5%E5%AD%90%E9%82%AE%E4%BB%B6 "电子邮件")及[XML](https://zh.wikipedia.org/wiki/XML "XML")的一些复杂数据。
### 字符集

base64 的替换表定义为字符串数组为

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```
### 编码原理

1. 将每三个字节划分为一组，得到 24 个二进制位
2. 将 24 个二进制位划分为 4 组，得到 4 组 6 个二进制位
3. 在每组前面补 0 凑足 8 位，扩展为 32 个二进制位，既 4 个字节
4. 根据 base64 的替换表查表替换得到 base64 编码
### 示例

例如，将字符串 `abc` 进行 base64 加密

`a` 的 ASCII 码为 `0x64` ，二进制表示为 `0110 0001`
`b` 的 ASCII 码为 `0x65` ，二进制表示为 `0110 0010`
`c` 的 ASCII 码为 `0x66` ，二进制表示为 `0110 0011`

将这 3 个 8 位字符转化为 4 个 6 位的二进制数即为

```
0110 0001 | 0110 0010 | 0110 0011
0110 00 | 01 0110 | 0010 01 | 10 0011
```

接着在高位补 0 凑足 8 位

```
0110 0001 | 0110 0010 | 0110 0011
0110 00 | 01 0110 | 0010 01 | 10 0011
0001 1000 | 0001 0110 | 0000 1001 | 0010 0011
```

### 代码实现

```C
#include "base64.h"

unsigned char *base64_encode(unsigned char *str)
{
    long len;
    long str_len;
    unsigned char *res;
    int i, j;
    // 定义base64编码表
    unsigned char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
    // 计算经过base64编码后的字符串长度
    str_len = strlen(str);
    if (str_len % 3 == 0)
        len = str_len / 3 * 4;
    else
        len = (str_len / 3 + 1) * 4;
  
    res = malloc(sizeof(unsigned char) * len + 1);
    res[len] = '\0';
  
    // 以3个8位字符为一组进行编码
    for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
    {
        res[i] = base64_table[str[j] >> 2];                                     // 取出第一个字符的前6位并找出对应的结果字符
        res[i + 1] = base64_table[(str[j] & 0x3) << 4 | (str[j + 1] >> 4)];     // 将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符
        res[i + 2] = base64_table[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)]; // 将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
        res[i + 3] = base64_table[str[j + 2] & 0x3f];                           // 取出第三个字符的后6位并找出结果字符
    }
  
    switch (str_len % 3)
    {
    case 1:
        res[i - 2] = '=';
        res[i - 1] = '=';
        break;
    case 2:
        res[i - 1] = '=';
        break;
    }
  
    return res;
}
  
unsigned char *base64_decode(unsigned char *code)
{
    // 根据base64表，以字符找到对应的十进制数据
    int table[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0,
                   63, 52, 53, 54, 55, 56, 57, 58,
                   59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0,
                   1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                   13, 14, 15, 16, 17, 18, 19, 20, 21,
                   22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26,
                   27, 28, 29, 30, 31, 32, 33, 34, 35,
                   36, 37, 38, 39, 40, 41, 42, 43, 44,
                   45, 46, 47, 48, 49, 50, 51};
    long len;
    long str_len;
    unsigned char *res;
    int i, j;
  
    // 计算解码后的字符串长度
    len = strlen(code);
    // 判断编码后的字符串后是否有=
    if (strstr(code, "=="))
        str_len = len / 4 * 3 - 2;
    else if (strstr(code, "="))
        str_len = len / 4 * 3 - 1;
    else
        str_len = len / 4 * 3;
  
    res = malloc(sizeof(unsigned char) * str_len + 1);
    res[str_len] = '\0';
  
    // 以4个字符为一位进行解码
    for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
    {
        res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4);           // 取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合
        res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2); // 取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合
        res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]);        // 取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合
    }
  
    return res;
}
```
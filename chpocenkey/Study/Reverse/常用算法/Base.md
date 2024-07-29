Base 算法是逆向中很常见，也是很简单的算法，基本上是新手逆向必备
## Base64

Base64 将 3 个 8 位字符转化为 4 个 6 位的二进制数（不足 8 位，高位补 0），通过查表来转化为字符

### 替换规则

1. 将每三个字节划分为一组，得到 24 个二进制位
2. 将 24 个二进制位划分为 4 组，得到 4 组 6 个二进制位
3. 在每组前面补 0 凑足 8 位，扩展为 32 个二进制位，既 4 个字节
4. 根据 base64 的替换表查表替换得到 base64 编码

base64 的替换表定义为字符串数组为

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

例如，将字符串 `abc` 进行 base64 加密

`a` 的 ascii 码为 `0x64` ，二进制表示为 `0110 0001`
`b` 的 ascii 码为 `0x65` ，二进制表示为 `0110 0010`
`c` 的 ascii 码为 `0x66` ，二进制表示为 `0110 0011`

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
    int i,j;  
//定义base64编码表  
    unsigned char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
//计算经过base64编码后的字符串长度  
    str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
    res=malloc(sizeof(unsigned char)*len+1);  
    res[len]='\0';  
//以3个8位字符为一组进行编码  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符  
        res[i+1]=base64_table[(str[j]&03)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        res[i+2]=base64_table[(str[j+1]0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        res[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符  
    }  
    switch(str_len % 3)  
    {  
        case 1:  
            res[i-2]='=';  
            res[i-1]='=';  
            break;  
        case 2:  
            res[i-1]='=';  
            break;  
    }  
    return res;  
}  

unsigned char *base64_decode(unsigned char *code)  
{  
//根据base64表，以字符找到对应的十进制数据  
    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,62,0,0,0,
             63,52,53,54,55,56,57,58,
             59,60,61,0,0,0,0,0,0,0,0,
             1,2,3,4,5,6,7,8,9,10,11,12,
             13,14,15,16,17,18,19,20,21,
             22,23,24,25,0,0,0,0,0,0,26,
             27,28,29,30,31,32,33,34,35,
             36,37,38,39,40,41,42,43,44,
             45,46,47,48,49,50,51
               };  
    long len;  
    long str_len;  
    unsigned char *res;  
    int i,j;
//计算解码后的字符串长度  
    len=strlen(code);  
//判断编码后的字符串后是否有=  
    if(strstr(code,"=="))  
        str_len=len/4*3-2;  
    else if(strstr(code,"="))  
        str_len=len/4*3-1;  
    else  
        str_len=len/4*3;  
    res=malloc(sizeof(unsigned char)*str_len+1);  
    res[str_len]='\0';  
//以4个字符为一位进行解码  
    for(i=0,j=0;i < len-2;j+=3,i+=4)  
    {
        res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
        res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
        res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
    }  
    return res;  
}
```
## Base58

base58 其实就是 base64 的变形，base58 的检索表比 base64 的检索表少了数字 `0` ，大写字母 `O` ，大写字母 `I` ，和小写字母 `l` ，以及 `+` 和 `/` 符号

base58 无法用整字节来转换表示 base58，所以开销会比base64 和 base16 大得多，但是有利于展示地址

由于不再是 64 位，所以不再使用原来三变四的加密方式，而是使用了新的加密方式：

>将密文与 58 进行辗转相除，直到商为 0，根据得到的模查表得到 base58 编码

base58 的替换表定义为字符串数组为

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

假设我们要对字节序列 `0x68656c6c6f`（即ASCII码中的字符串 `hello` ）进行Base58编码

1. **将数据转换为整数**：`0x68656c6c6f` 转换为十进制是 1953256349
2. **计算Base58字符**：
    - 1953256349 ÷ 58 = 33679127...49
    - 33679127 ÷ 58 = 580781...55
    - 580781 ÷ 58 = 10014...31
    - 10014 ÷ 58 = 172...42
    - 172 ÷ 58 = 2...54
    - 2 ÷ 58 = 0...2
    - 查找字符表，49, 55, 31, 42, 2 对应的字符分别是"1", "7", "F", "6", "2"。
3. **处理前导零**：由于原始数据的第一个字节是"h"（0x68），不是零，因此编码结果为"1" + "1" + "7" + "F" + "6" + "2"。
4. **结果**：编码结果为"1A2E3H"。

### 代码实现

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char* base58_encode(unsigned char* str)  // 编码
{
    // 定义 base58 编码表
    static char* nb58 =(char*)"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t len = strlen((char*)str);
    size_t rlen = (len / 2 + 1) * 3;
    unsigned char* ret = (unsigned char*)malloc(rlen + len);
    unsigned char* src = ret + rlen;
    unsigned char* rptr = ret + rlen;
    unsigned char* ptr, * e = src + len - 1;
    size_t i;
    memcpy(src, str, len);
    while (src <= e)
    {
        if (*src)
        {
            unsigned char rest = 0;
            ptr = src;
            while (ptr <= e)
            {
                unsigned int c = rest * 256;
                rest = (c + *ptr) % 58;
                *ptr = (c + *ptr) / 58;
                ptr++;
            }
            --rptr;
            *rptr = nb58[rest];
        }
        else
        {
            src++;
        }
    }
    for (i = 0; i < ret + rlen - rptr; i++)
        ret[i] = rptr[i];
    ret[i] = 0;
    return ret;
}
unsigned char* base58_decode(unsigned char* src)  // 解码
{
    static char b58n[] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
        -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
        -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    size_t len = strlen((char*)src);
    size_t rlen = (len / 4 + 1) * 3;
    unsigned char* ret = (unsigned char*)malloc(rlen);
    unsigned char* rptr = ret + rlen;
    size_t i;
    unsigned char* ptr;
    for (i = 0; i < len; i++)
    {
        char rest = b58n[src[i]];
        if (rest < 0)
        {
            free(ret);
            return NULL;
        }
        for (ptr = ret + rlen - 1; ptr >= rptr; ptr--)
        {
            unsigned int c = rest + *ptr * 58;
            *ptr = c % 256;
            rest = c / 256;
        }
        if (rest > 0)
        {
            rptr--;
            if (rptr < ret)
            {
                free(ret);
                return NULL;
            }
            *rptr = rest;
        }
    }
    for (i = 0; i < ret + rlen - rptr; i++)
        ret[i] = rptr[i];
    ret[i] = 0;
    return ret;
}
```

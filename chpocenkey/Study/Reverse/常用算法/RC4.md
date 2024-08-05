RC4 是对称加密算法，通过密钥 key 和 S 盒生成密钥流，明文逐字节异或 S 盒，同时 S 盒也会发生改变。所以加密与解密使用了相同的函数和密钥K

RC4 加密的强度主要来源于密钥的安全性，如果密钥泄露，则能直接解密出明文
## 算法分析

### 1. S 盒初始化

1. 初始化存储 0-255 字节的 Sbox
2. 将 key 填充到 256 个字节的数组中，该数组被称为 Tbox
3. 交换 s\[i\] 和 s\[j\]，其中 i 从 0 开始直到 255 结束，j是 S\[i\] 和 T\[i\] 组合得出的下标

![RC4Init.png](https://gitee.com/chpocenkey/images/raw/master/RC4Init.png)

**算法实现**

```C
void RC4_init(unsigned char *s, unsigned char *key, unsigned long Len)
{
    int i = 0, j = 0;
    unsigned char k[256] = {0};
    unsigned char tmp = 0;
    for (int i = 0; i < 256; i++)
    {
        s[i] = i;
        k[i] = key[i % Len];
    }
    for (int i = 0; i < 256; i++)
    {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}
```

### 2. 异或生成密文

1. 交换一次 Sbox 的数据
2. 将明文与 S\[S\[i\] + S\[j\]\] 进行异或生成密文

![RC4Encrypt.png](https://gitee.com/chpocenkey/images/raw/master/RC4Encrypt.png)

**算法实现**

```C
void RC4_enc_dec(unsigned char *s, unsigned char *Data, unsigned long Len)
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for (k = 0; k < Len; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] ^= s[t];
    }
}
```

## 算法实现

```C

#include <stdio.h>
#include <string.h>
  
/*初始化函数*/
void RC4_init(unsigned char *s, unsigned char *key, unsigned long Len)
{
    int i = 0, j = 0;
    unsigned char k[256] = {0};
    unsigned char tmp = 0;
    for (int i = 0; i < 256; i++)
    {
        s[i] = i;
        k[i] = key[i % Len];
    }
    for (int i = 0; i < 256; i++)
    {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}
  
/*加解密*/
void RC4_enc_dec(unsigned char *s, unsigned char *Data, unsigned long Len)
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for (k = 0; k < Len; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] ^= s[t];
    }
}
```



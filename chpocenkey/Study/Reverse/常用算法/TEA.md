## TEA

TEA 全称 Tiny Encrypt Algorithm，微型加密算法

在 CTF 逆向分析中经常会出现 TEA 或者魔改了 DELTA 的 TEA 算法

### 算法原理

![TEA.png](https://gitee.com/chpocenkey/images/raw/master/TEA.png)

明文长度分组为 64 位（ 8 字节），密钥长度为 128 位（ 16 字节），明文和密钥进入 32 轮循环，得到最后的 64 位密文

明文被分为 2 个 32 位无符号整数，密钥为 4 个 32 位无符号整数
### 算法实现

```C
#include "tea.h"

void encrypt(uint32_t *entryData, uint32_t const *key)
{
    uint32_t x = entryData[0];
    uint32_t y = entryData[1];
    uint32_t sum = 0;
    uint32_t delta = 0x9e3779b9;
  
    for (int i = 0; i < 32; i++)
    {
        sum += delta;
        x += ((y << 4) + key[0]) ^ (y + sum) ^ ((y >> 5) + key[1]);
        y += ((x << 4) + key[2]) ^ (x + sum) ^ ((x >> 5) + key[3]);
    }
    entryData[0] = x;
    entryData[1] = y;
}
  
void decrypt(uint32_t *v, uint32_t const *k)
{
    uint32_t v0 = v[0], v1 = v[1], i; // 这里的sum是0x9e3779b9*32后截取32位的结果，截取很重要。
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta << 5;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++)
    {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}
```
## XTEA

XTEA 是 TEA 的升级版，增加了更多的密钥表，移位和异或等操作

### 算法原理

1. 初始化

将 128 位密钥划分为 4 个 32 位的子密钥 $[k_0, k_1,k_2, k_3]$ ，并明文块分成两个 32 位的子块 $[v_0, v_1]$ ，然后初始化变量 $sum$ 和 $delta$ ，其中 $sum$ 的初始值为 0， $delta$ 的值为固定的常数 $0x9E3779B9$

2. 迭代加密

对每个明文块 $[v_0, v_1]$ ，循环执行加密操作 $num\_rounds$ 次，每次加密操作中，都使用子密钥 $[k_0, k_1, k_2, k_3]$ 对明文块 $[v_0, v_1]$ 进行加密，加密结果保存在 $N$ 数组中

在每次加密操作中，先将 $F$ 左移 4 位，然后将结果与 $F$ 右移 5 位的结果进行异或运算，
再将结果加上 $F$ 的值，最后再将结果与 $A$ 和 $M$ 进行异或运算，其中 $T$ 表示 $A$ 的低 2 位，即 $A$ 对 4 取模所得的余数

然后将 $A$ 加上固定常数 $delta$

接下来，将 $G$ 左移 4 位，然后将结果与 $G$ 右移 5 位的结果进行异或运算，再将结果加上 $G$ 的值，最后再将结果与 $A$ 和 $H$ 进行异或运算，其中 $D$ 表示 $A$ 向右移 11 位，并对 4 取模所得的余数

最后将加密结果保存在输出数组中

![XTEA.png](https://gitee.com/chpocenkey/images/raw/master/XTEA.png)
### 算法实现

```C
#include "xtea.h"
  
void encrypt(uint32_t v[2], uint32_t const key[4]) {
  unsigned int num_rounds = 32;
  unsigned int i;
  uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
  for (i = 0; i < num_rounds; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
  }
  v[0] = v0;
  v[1] = v1;
}
  
void decrypt(uint32_t v[2], uint32_t const key[4]) {
  unsigned int num_rounds = 32;
  unsigned int i;
  uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
  for (i = 0; i < num_rounds; i++) {
    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    sum -= delta;
    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
  }
  v[0] = v0;
  v[1] = v1;
}
```
## XXTEA

XXTEA，又称 Corrected Block TEA，是 XTEA 的升级版
### 算法原理

### 算法实现

```C
#include <stdint.h>
#include <stdio.h>
#define DELTA 0x9e3779b9
#define MX                                   \
  (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ \
   ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
  
void btea(uint32_t *v, int n, uint32_t const key[4]) {
  uint32_t y, z, sum;
  unsigned p, rounds, e;
  if (n > 1) /* Coding Part */
  {
    rounds = 6 + 52 / n;
    sum = 0;
    z = v[n - 1];
    do {
      sum += DELTA;
      e = (sum >> 2) & 3;
      for (p = 0; p < n - 1; p++) {
        y = v[p + 1];
        z = v[p] += MX;
      }
      y = v[0];
      z = v[n - 1] += MX;
    } while (--rounds);
  } else if (n < -1) /* Decoding Part */
  {
    n = -n;
    rounds = 6 + 52 / n;
    sum = rounds * DELTA;
    y = v[0];
    do {
      e = (sum >> 2) & 3;
      for (p = n - 1; p > 0; p--) {
        z = v[p - 1];
        y = v[p] -= MX;
      }
      z = v[n - 1];
      y = v[0] -= MX;
      sum -= DELTA;
    } while (--rounds);
  }
}

int main() {
  uint32_t v[3] = {0x44434241, 0x48474645, 0x0};
  uint32_t const k[4] = {0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF11};
  int n = 2;
  printf("Data: %s\n", (char *)v);
  printf("Data: %u %u\n", v[0], v[1]);
  btea(v, n, k);
  printf("Encrypt Data: %u %u\n", v[0], v[1]);
  btea(v, -n, k);
  printf("Decrypt Data: %u %u\n", v[0], v[1]);
  printf("Decrypt Data: %s\n", (char *)v);
  
  return 0;
}
```
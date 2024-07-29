TEA全称Tiny Encrypt Algorithm。在CTF逆向分析中经常会出现Tea或者魔改了DELTA的TEA算法。

## 算法原理

明文长度分组为64位（8字节），密钥长度为128位（16字节），明文和密钥进入32轮循环，得到最后的64位密文。其中magic number DELTA是由黄金分割点得到。
## 算法实现

```
#include<stdio.h>
#include<stdint.h>
#define DELTA 0x9981abcd

void tea_encrypt(unsigned int* v, unsigned int* key) {
  unsigned int l = v[0], r = v[1], sum = 0;
  for (size_t i = 0; i < 32; i++) { //进行32次迭代加密，Tea算法作者的建议迭代次数
    l += (((r << 4) ^ (r >> 5)) + r) ^ (sum + key[sum & 3]);
    sum += DELTA; //累加Delta的值
    r += (((l << 4) ^ (l >> 5)) + l) ^ (sum + key[(sum >> 11) & 3]); //利用多次双位移和异或将明文与密钥扩散混乱，并将两个明文互相加密
  }
  v[0] = l;
  v[1] = r;
}

void tea_decrypt(unsigned int* v, unsigned int* key) {
  unsigned int l = v[0], r = v[1], sum = 0;
  sum = DELTA * 32; //32次迭代累加后delta的值
  for (size_t i = 0; i < 32; i++) {
    r -= (((l << 4) ^ (l >> 5)) + l) ^ (sum + key[(sum >> 11) & 3]);
    sum -= DELTA;
    l -= (((r << 4) ^ (r >> 5)) + r) ^ (sum + key[sum & 3]);
  }
  v[0] = l;
  v[1] = r;
}


int main(int argc, char const *argv[])
{
    unsigned int key1[4]={0xa3eeb7be,0x50e7de9a,0x6dbcc2bc,0x78591fad};//key1
    unsigned int key2[4]={0x78591fad,0x6dbcc2bc,0xa3eeb7be,0x50e7de9a};//key2
    unsigned int v1[2] = {0x556E2853,0x4393DF16};
    unsigned int v2[2] = {0x1989FB2B,0x83F5A243};
    
    //encrypt(v1,key1);
    //printf("tea_encrypt:%x %x\n",v1[0],v1[1]);
    //encrypt(v2,key2);
    //printf("tea_encrypt:%x %x\n",v2[0],v2[1]);
    tea_decrypt(v1,key1);
    printf("tea_decrypt:%x %x\n",v1[0],v1[1]);
    tea_decrypt(v2,key2);
    printf("tea_decrypt:%x %x\n",v2[0],v2[1]);
    return 0;
}

//tea_decrypt:c0cacd59 38bb7623
//tea_decrypt:8757d16 a520cece
}
```

## 发现

ida pro 的 findcrypt 插件
peid 的 kanal 插件

## XTEA

TEA升级版XTEA，增加了更多的密钥表，移位和异或等操作

算法实现

```
#include <stdio.h>
#include <stdint.h>
 
/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
 
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}
 
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
 
int main()
{
    uint32_t v[2]={1,2};
    uint32_t const k[4]={2,2,3,4};
    unsigned int r=32;//num_rounds建议取值为32
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    encipher(r, v, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    decipher(r, v, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    return 0;
}
```
## XXTEA

XXTEA，又称Corrected Block TEA，是XTEA的升级版

算法实现

```
#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
 
void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52/n;
        sum = 0;
        z = v[n-1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++)
            {
                y = v[p+1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = rounds*DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}
 
 
int main()
{
    uint32_t v[2]= {1,2};
    uint32_t const k[4]= {2,2,3,4};
    int n= 2; //n的绝对值表示v的长度，取正表示加密，取负表示解密
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    btea(v, n, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    btea(v, -n, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    return 0;
}
```
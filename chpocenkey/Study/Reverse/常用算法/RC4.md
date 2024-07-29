RC4是对称加密算法，通过密钥key和S盒生成密钥流，明文逐字节异或S盒，同时S盒也会发生改变。所以加密与解密使用了相同的函数和密钥K

RC4加密的强度主要来源于密钥的安全性，如果密钥泄露，则能直接解密出明文。
## 算法分析

### 1. S盒初始化

第一个 256 循环：初始化为 0-255
第二个 256 循环：根据密钥 K，交换密钥盒 S

算法实现

```C
for i=0 to 255 do
	S[i]=i
j=0
for i=0 to 255 do
	j = (j+S[i] + key[i mod keylength]) mod 256
	swap(S[i],S[j])//交换S[i]和S[j]
```

### 2. 异或生成密文

1. 根据明文长度生成相同长度的密钥流
2. 密钥流和明文异或生成密文

算法实现

```C
i,j=0;
for r=0 to len(明文) do:
	i = (i+1)mod 256
	j = (j+S[i]) mod 256
	swap(S[i],S[j])
	t = (S[i]+S[j]) mod 256
	data[r] ^= S[t]//生成密文
```

## 算法实现

```C
#include<stdio.h>
#include<string.h>

struct rc4_state
{
    int x, y, m[256];
}rc4_state;

void rc4_setup( struct rc4_state *s, unsigned char *key,  int length );
void rc4_crypt( struct rc4_state *s, unsigned char *data, int length );

void rc4_setup( struct rc4_state *s, unsigned char *key,  int length )
{
    int i, j, k, *m, a;

    s->x = 0;
    s->y = 0;
    m = s->m;

    for( i = 0; i < 256; i++ )
    {
        m[i] = i;
    }

    j = k = 0;

    for( i = 0; i < 256; i++ )
    {
        a = m[i];
        j = (unsigned char) ( j + a + key[k] );
        m[i] = m[j]; m[j] = a;
        if( ++k >= length ) k = 0;
    }
}

void rc4_crypt( struct rc4_state *s, unsigned char *data, int length )
{ 
    int i, x, y, *m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for( i = 0; i < length; i++ )
    {
        x = (unsigned char) ( x + 1 ); 
        a = m[x];
        y = (unsigned char) ( y + a );
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char) ( a + b )];
    }

    s->x = x;
    s->y = y;
}


int main()
{
    struct rc4_state rc4_ctx;
    char* key = "abelxuabelxu";
    unsigned char content[256] = "0123456789abcdef";
    //encrypt为RC4(content,key)得到的密文
    unsigned char encrpyt[256] = {0x7d,0x71,0x12,0xe2,0x97,0xb1,0x24,0xef,0xc4,0xa9,0xe2,0xe3,0xab,0xf4,0x74,0xd7};
    memset(&rc4_ctx,0,sizeof(rc4_state));
    rc4_setup(&rc4_ctx,key,strlen(key));
    rc4_crypt(&rc4_ctx,content,strlen(content));
    for (int i = 0; i < strlen(content); i++)
        printf("%2.2x", content[i]);
    printf("\n");
    rc4_setup(&rc4_ctx,key,strlen(key));
    rc4_crypt(&rc4_ctx,encrpyt,strlen(encrpyt));
    printf("%s\n");
    printf("\n");
}
```

## 识别

虽然工具无法直接识别出 RC4 算法，但是 RC4 算法比较简单，主要的是 3 个 for 循环，前两个 256 循环为 S 盒初始化，最后一个循环异或生成密文

可以通过调试初始化代码找到每次 RC4 的密钥 key
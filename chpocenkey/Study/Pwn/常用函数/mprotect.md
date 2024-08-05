## 函数原型

``` C++
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);
```

`mprotect()` 函数把自 `start` 开始，长度为 `len` 的内存区的保护属性修改为 `prot` 指定的值

`prot` 可以取以下几个值，并且可以用 `"|"` 将几个属性合起来用

- `PROT_READ` 表示内存段内的内容可读
- `PROT_WRITE` 表示内存段内的内容可写
- `PROT_EXEC` 表示内存段内的内容可执行
- `PROT_NONE` 表示内存段中的内容根本无法访问
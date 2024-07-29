## 简介

gdb 是 Linux 系统中一个非常好相应且强大的调试工具，采用纯命令行的形式进行调试
## 常用快捷键

| **命令**                        | 简写  | 效果                                |
| ----------------------------- | --- | --------------------------------- |
| `list`                        | `l` | 查看代码（pwn 题中并不常见，主要用于调试）           |
| `break`                       | `b` | 设置断点                              |
| `run`                         | `r` | 运行程序                              |
| `next`                        | `n` | 单步步过                              |
| `step`                        | `s` | 单步步入                              |
| `continue`                    | `c` | 恢复程序运行直到程序结束或到达下一个断点              |
| `print`                       | `p` | 查看当前程序的运行数据                       |
| `watch`                       |     | 观察某个表达式的值是否有变化                    |
| `quit`                        | `q` | 退出调试                              |
| `info b`                      |     | 查看断点                              |
| `enable`                      |     | 激活断点                              |
| `disable`                     |     | 禁用断点                              |
| `del`                         |     | 删除断点                              |
| `stack 100`                   |     | 显示栈中前100项                         |
| `find xxx`                    |     | 快速查找                              |
| `s`                           |     | 按字符串输出                            |
| `start`                       |     | 运行到 main 函数                       |
| `set $eip=a`                  |     | 修改变量值                             |
| `jump 10`                     | j   | 跳转到第十行                            |
| `display`                     |     | 查看汇编                              |
| `x`                           |     | 检查内存                              |
| `parseheap`                   |     | 分析内存堆（gdb 的 python 扩展命令）          |
| `hexdump [options] [file...]` |     | 显示文件或其他输入流的内容，通常以十六进制和 ASCII 形式显示 |
| `/10i`                        |     | 指定检查的格式和数量，这里 `10i` 表示检查 10 个指令   |
| `$pc`                         |     | 指定检查对象为程序计数器                      |
| `finish`                      |     | 在一个函数内部，执行到当前函数返回，然后停下等待命令        |
#### 查看汇编
- **`disassemble`**：查看当前函数的汇编代码
- **`disassemble memory_address`**：查看某个地址的汇编代码
- `disassemble start_address, end_address`：查看当前函数某个范围内的汇编代码
#### display
`display /20i $pc`
##### layout
`layout asm`
##### layout pro
`layout split`
`layout asm`
##### x
`x /10i $pc`****

- **`info functions`**：列出所有函数名称
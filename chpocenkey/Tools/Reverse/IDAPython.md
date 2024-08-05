## 简介

IDAPython在IDA中集成了Python解释器，除了提供了Python功能外，使用这个插件还可以编写实现IDC脚本语言的所有Python脚本。

IDAPython显著优势在于，它可以充分利用Python强大的数据处理能力及所有的Python模块。

IDAPython还具有IDA SDK的大部分功能，与IDC相比，使用它可以编写功能更加强大的脚本。

IDAPython有一个缺点就是文档资源太少，容易造成障碍

## 主要模块

1. idaapi.py:　　   负责访问核心IDA API。
2. idautils.py:       提供大量的使用函数。
3. idc.py:            负责提供IDC中所有函数的功能。
## 使用方式

- `Alt+F7` ：运行 IDAPython 脚本文件
- `Ctrl+F3` ：单行执行 IDAPython
- `Alt+F9` ：查看所有的 IDAPython 脚本文件
- `Shift+F12` ：调出界面
- 写一个脚本文件，通过 `File -> Script file` 选择该脚本文件引用
- 在 IDA 底部写命令
## 简单操作
### 获取地址

当前地址获取使用 **idc.here()** 函数 或者 **idc.get_screen_ea()** 函数

最小地址可以使用: **ida_ida.inf_get_min_ea()**

最大地址可以使用: **ida_ida.inf_get_max_ea()**

当前选择地址的开始: **idc.read_selection_start()**

当前选择地址的结束:**idc.read_selection_end()**

如果判断地址是否存在可以使用: **idaapi.BADADDR**
### 获取数值
| 新的函数                     | 说明               |
| ------------------------ | ---------------- |
| idc.get_wide_byte(addr)  | 以字节为单位获取地址处的值    |
| idc.get_wide_word(addr)  | 同上. 以2字节(字)的单位获取 |
| idc.get_wide_dword(addr) | 4字节              |
| idc.get_qword(addr)      | 8字节              |
### 数值操作
| 新函数                               | 说明                        |
| --------------------------------- | ------------------------- |
| ida_bytes.patch_byte(addr,value)  | 修改addr地址的值为value.每次修改一个字节 |
| ida_bytes.patch_word(addr,value)  | 同上一次修改变为2个字节              |
| ida_bytes.patch_Dword(addr,value) | 4                         |
| ida_bytes.patch_Qword(addr,value) | 8                         |

## 常用脚本

**测试脚本**

```
#coding:utf-8
from idaapi import *
danger_funcs = ["IsProcessorFeaturePresent"]  # 需要寻找的函数名
for func in danger_funcs:
    addr = LocByName( func ) 
    if addr != BADADDR:
       #找到交叉引用的地址
        cross_refs = CodeRefsTo( addr, 0 )
        print "Cross References to %s" % func 
        print "-------------------------------"
        for ref in cross_refs: 
            print "%08x" % ref
             # 函数的颜色为红色
            SetColor( ref, CIC_ITEM, 0x0000ff)
```

**SMC 修改脚本**

```
import idc
addr = 0x401500  # encrypt 函数的地址
for i in range(187):
    b = get_bytes(addr + i, 1)
    idc.patch_byte(addr + i, ord(b) ^ 0x41)
```
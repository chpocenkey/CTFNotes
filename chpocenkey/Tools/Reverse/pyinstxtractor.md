## 简介

将 python 打包的程序反编译为 python 字节码
## 安装

```Github
https://github.com/extremecoders-re/pyinstxtractor
```
## 使用

```
python pyinstxtractor.py test.exe
```

一个 extracted 文件夹，里面有 struct 文件和 test 文件（和解包的名称一样），但是用 pyinstaller 将 py 文件生成 exe 文件时，会将文件头去掉，所以需要复原文件头

插入前 12 个字节，再修改后缀为 `.pyc` ，即可用 [[uncompyle6]] 反编译得到 `.py` 文件
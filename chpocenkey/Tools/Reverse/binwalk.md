## 介绍

`binwalk` 是一个快速，易于使用的工具，用于分析、逆向工程和提取固件映像

官方给出的用途是提取固件镜像，但也可以用于提取隐藏信息

## 安装

```Linux
$ sudo apt install binwalk
```

## 快速入门
### 扫描固件

`binwalk` 可以扫描许多嵌入式文件类型和文件系统的固件镜像

### 文件提取

可以使用 `binwalk`   的 `-e` 参数来提取固件中的文件

```Linux
$ binwalk -e firmware.bin
```

指定 `-M` 选项递归扫描文件

```Linux
$ binwalk -Me firmware.bin
```

指定 `-r` 选项，自动删除无法提取的任何文件签名或大小为 0 的文件

```Linux
$ binwalk -Mre firmware.bin
```
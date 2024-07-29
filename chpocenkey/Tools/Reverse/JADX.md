## 简介

jadx 是一个非常好用的反编译工具，主要用于 java、apk反编译，可以处理大部分反编译的需求

jadx 有命令行式的 jadx-cli，也有图形化界面的 jadx-gui，此处特指 jadx-gui
## 下载

jadx 本身是一个开源项目，源代码已经在 [GitHub](https://github.com/skylot/jadx) 上开源

## 使用

双击 jadx-gui 即可运行（ Windows 平台需要使用 jadx-gui.bat，此处使用 Windows 环境讲解）

可以选择直接将文件拖上去，也可以打开后再选择文件，基本上编译成 Java 虚拟机能识别的字节码都可以反编译

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717181543.png)

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717181613.png)

## 技巧

### 搜索

jadx 的搜索功能非常强大

可以在导航选项卡页面选择，其快捷键是 `Ctrl+Shift+F`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717182055.png)

也使用主页面的导航栏下的问号打开

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717182213.png)

打开之后对搜索内容进行过滤就非常容易了

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717182337.png)

### 查找引用

jadx 与 IDA Pro 一样提供查找引用功能，只需要选中后右键，再选择查找用例即可，其快捷键为 `x`

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717182527.png)

### 撤回

jadx 可以使用 `esc` 返回到你之前所在的位置，个人认为是比较便捷的地方

### 一键导出 Gradle 工程

jadx 还支持将反编译后的项目，直接导出成一个 Gradle 编译的工程

可以通过文件下的保存为 Gradle 工程来使用这个功能

![image.png](https://gitee.com/chpocenkey/images/raw/master/20240717182855.png)

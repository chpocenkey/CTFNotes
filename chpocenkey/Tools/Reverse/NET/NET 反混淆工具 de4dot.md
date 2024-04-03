#### 简介
.NET 反混淆和脱壳工具。目前 .NET 的逆向接触较少，只是稍做介绍
#### 下载安装
##### 下载源码
项目地址：[https://github.com/de4dot/de4dot](https://github.com/de4dot/de4dot)
记得一定要用 git ，不要直接打包 zip

	git clone https://github.com/de4dot/de4dot.git 


![[Pasted image 20240403194334.png]]

##### 编译选择
这里有两个解决方案文件，一个是基于**.NET Core的(de4dot.netcore.sln)**，一个是基于**.NET Framework的(de4dot.netframework.sln)**
如果使用.net core版本，需要安装netcoreapp3.1和netcoreapp2.1
如果使用.net framework版本，需要安装net 35和net45
我这里直接编译的.net framework版本，没有编译.net core版本了。

##### 编译
1. 直接用 VS 打开 de4dot.netframework.sln（de4dot.netcore.sln 也可以，但是我是用的 de4dot.netframework.sln）![[Pasted image 20240403201112.png]]
2. 选择 `Release` 和 `Debug` 都可以，编译后选择相应的文件夹即可
3. 点击 `生成 > 生成解决方案`，编译获取可执行文件![[Pasted image 20240403201118.png]]
4. 进入相应文件夹即可发现相应可执行文件![[Pasted image 20240403201151.png]]

#### 使用
直接将文件拖入即可简单使用
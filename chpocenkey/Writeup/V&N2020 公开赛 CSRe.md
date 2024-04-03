1. exeinfo![[Pasted image 20240403191731.png]].NET 语言编写的 32 位 .exe 文件，de4dot 加密
2. 直接使用 de4dot 工具解密![[Pasted image 20240403191905.png]]
3. 查看发现已经脱壳
4. .NET 语言编写的 32 位文件，用 dnSpy 查看![[Pasted image 20240403192503.png]]
5. 查看 Class3.method_0，发现是一个 SHA1 加密的函数![[Pasted image 20240403192621.png]]
6. 查看 @class.method_0 ![[Pasted image 20240403193140.png]]发现大概意思是比较两个字符串，并将两个字符串每一位的异或值相加得到和，若两个字符串相同，则结果为 0
7. 进入 [MD5解密](https://www.somd5.com/) 网址解密![[Pasted image 20240403192858.png]]![[Pasted image 20240403193033.png]]得到 str="1415", text="etur"
8. 得到 flag="flag{" + str + text + "}"，即 flag{1415etur}
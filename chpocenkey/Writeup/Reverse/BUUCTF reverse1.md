1. 获取文件 `reverse_1` ，先放到 `exeinfope` 中判断，发现无壳
![[BUUCTF reverse1 1.png]]

2. 将文件用 `64位IDA Pro` 打开查看
![[BUUCTF reverse1 2.png]]

3. 先用 `Shift + F12` 查看字符串，发现一个 `this_is_the_right_flag!\n`
![[BUUCTF reverse1 3.png]]

4. 进入查看
![[BUUCTF reverse1 4.png]]

5. `Ctrl + x` 查看交叉引用
![[BUUCTF reverse1 5.png]]

6. 进入查看
![[BUUCTF reverse1 6.png]]

7. `F5` 查看伪代码
![[BUUCTF reverse1 7.png]]

8. 发现比较函数，进入查看 `Str2` 值，发现 `{Hello_world}` ，猜测为 `flag`
![[BUUCTF reverse1 8.png]]

9. 提交 `flag`
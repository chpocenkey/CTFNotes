1. 获取文件 `reverse_2` ，先放到 `exeinfope` 中判断，发现是一个无壳ELF文件
![[BUUCTF reverse2 1.png]]

2. 将文件用 `64位IDA Pro` 打开查看
![[BUUCTF reverse2 2.png]]

3. 先用 `Shift + F12` 查看字符串，发现一个 `this_is_the_right_flag!`
![[BUUCTF reverse2 3.png]]

4. 进入查看
![[BUUCTF reverse2 4.png]]

5. `Ctrl + x` 查看交叉引用
![[BUUCTF reverse2 5.png]]

6. `F5` 查看伪代码，发现代码将 `flag` 的 `i` 和 `r` 改为 `1`
![[BUUCTF reverse2 6.png]]

7.  发现比较函数，进入查看 `flag` 值，发现 `{hacking_for_fun}` ，猜测为 `flag`
![[BUUCTF reverse2 8.png]]

8. 因为在主函数里面代码将 `flag` 的 `i` 和 `r` 都替换成了 `1` ，所以直接对 `flag` 进行变换，得到结果 `{hack1ng_fo1_fun}`
9. 提交 `flag`
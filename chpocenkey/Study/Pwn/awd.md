## 连接
- ssh 连接
	- `ssh -p [端口号] [用户名]@[远程主机]`
- xshell 连接
- 文件下载 `scp -P 2222 -r team2@192-168-1-181.pvp4614.bugku.cn:/home/ctf C:\Users\pockey\Desktop`
## 密码 
改密码
`passwd` 修改密码 

## 部署方式 
xinetd
- `/etc/xinetd`
- `/home/ctf`
- `/var/www/html`
##  分工
### 运维
- 快速熟悉服务器配置
- 备份数据
	- 将附件保存
### 攻击
- 现场快速根据漏洞写出利用程序，读取对手 `flag`
- 攻击自动化，同时攻击多个对手，攻击成功自动提交 `flag`
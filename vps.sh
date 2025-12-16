安装 Fail2ban：

```
sudo apt install fail2ban
sudo apt install rsyslog
```

官方推荐的做法是利用 jail.local 来进行自定义设置：

```bash
sudo nano /etc/fail2ban/jail.local
```

参照以下配置文件来进行自己的配置（记得删注释）：

```
[sshd]
ignoreip = 127.0.0.1/8 # 白名单
enabled = true
filter = sshd
port = 22 # 端口，改了的话这里也要改
maxretry = 5 # 最大尝试次数
findtime = 300 # 多少秒以内最大尝试次数规则生效
bantime = 600 # 封禁多少秒，-1是永久封禁（不建议永久封禁）
action = %(action_)s[port="%(port)s", protocol="%(protocol)s", logpath="%(logpath)s", chain="%(chain)s"] # 不需要发邮件通知就这样设置
banaction = iptables-multiport # 禁用方式
logpath = /var/log/auth.log # SSH 登陆日志位置
```

```
[sshd]
ignoreip = 127.0.0.1/8
enabled = true
filter = sshd
port = 2025
maxretry = 5
findtime = 300
bantime = 600
action = %(action_)s[port="%(port)s", protocol="%(protocol)s", logpath="%(logpath)s", chain="%(chain)s"]
banaction = iptables-multiport
logpath = /var/log/auth.log
```



配置完成后需要重新启动 Fail2ban 服务以应用配置更改：

```
sudo systemctl restart fail2ban
```

检查 Fail2ban 的状态以确保它正常运行：

```
sudo fail2ban-client status
```

查看该 `sshd` jail 的详细状态以及被禁 IP 列表

```
sudo fail2ban-client status sshd
```

注：部分debian机器安装失败，发现是 `/var/log/auth.log` 这个文件不存在，因为没有预装`rsyslog`

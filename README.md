# Network Redirector

需管理员权限运行

该工具目标为重定向zwift地址与端口从而绕过IPv6的部分端口封锁

目前该工具仅支持IPv6/TCP协议.

### Step 1 配置
修改``C:\Windows\System32\drivers\etc\hosts``文件
将下列内容填入到hosts当中
```
6666::6666 us-or-rly101.zwift.com secure.zwift.com cdn.zwift.com launcher.zwift.com
```
* __注意:__ 如果本机有类似``v2rayN``,``clash``等相关代理软件记得配置路由规则避免无法重注入
* 如果本机为``zoffline server``那请将``server``地址填写本地的局域网IPv6地址
* 该工具与反作弊相关软件同时运行可能会导致封禁,谨慎使用!


### 关于驱动卸载
```
    sc stop WinDivert
    sc delete WinDivert
```
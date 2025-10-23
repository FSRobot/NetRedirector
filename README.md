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
* __注意:__ 如果本机有类似``v2rayN,clash``等相关代理软件记得配置路由规则避免无法重注入
* 如果本机为``zoffline server``请勿使用此软件!
* 该工具与反作弊相关软件同时运行可能会导致封禁,谨慎使用!

### 关于驱动卸载
```
    sc stop WinDivert
    sc delete WinDivert
```

### 关于开发配置
* 配置vcpkg
```
vcpkg install spdlog fmt
```
* 修改CMakePresets.json
```
    QTDIR指向你的qt目录
    CMAKE_TOOLCHAIN_FILE指向你的vcpkg目录
```

* 配置qt 6.8.3
* 使用msvc发布

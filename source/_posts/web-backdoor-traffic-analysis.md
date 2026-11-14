---
title: 2026CCF-系统后门用户分析
date: 2026-11-15 03:30:00
tags:
  - 流量分析
  - Wireshark
categories:
  - 蓝队
---

## 锁定战场

打开 Wireshark 后，我们面对成百上千个数据包，不能漫无目的地乱翻。首先要做的是"鸟瞰"全局。

统计 → 协议分级

![协议分级](/images/traffic/01-protocol.png)

可以看到 HTTP 的包最多，其他的几乎没有，所以锁定 Web 流量。

然后再看看是哪个端口，统计 → 会话，可以看到 8022 的流量最大。

![会话](/images/traffic/02-sessions.png)

到此为止，我们就可以锁定战场：Web，端口 8022。

## 定位攻击者

找一下有异常行为的 IP，比如这个，大量的请求不存在的地址，可能是在扫描。

![扫描](/images/traffic/03-scanner.png)

## 定位攻击路径

这个题目是后门排查，一般都是 POST 请求，所以可以缩小范围。

![POST](/images/traffic/04-post.png)

`/upload.php` 是攻击点。

`/uploads/php_68525da04b2c37.31016234.php` 是后门。

然后再分析数据包，来看看都执行了什么命令。

![命令执行](/images/traffic/05-command.png)

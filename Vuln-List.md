# 项目列表

- [Spring Cloud Gateway](#Spring-Cloud-Gateway)
- [Zabbix监控系统](#Zabbix监控系统)
- [向日葵](#向日葵)
- [钉钉办公软件](#钉钉办公软件)

# 漏洞列表

### Spring Cloud Gateway
- CVE-2022-22947 Spring Cloud Gateway远程代码执行漏洞
  - 漏洞影响版本:**Spring Cloud Gateway < 3.1.1、Spring Cloud Gateway < 3.0.7、Spring Cloud Gateway 其他已不再更新的版本**
  - 漏洞介绍及修复建议:https://spring.io/blog/2022/03/01/spring-cloud-gateway-cve-reports-published
  - POC/EXP:https://github.com/vulhub/vulhub/blob/master/spring/CVE-2022-22947/README.zh-cn.md

### Zabbix监控系统
- CVE-2022-23131 Zabbix登录绕过漏洞
  - 漏洞影响版本:**5.4.0 - 5.4.8、6.0.0alpha1**
  - 漏洞介绍及修复建议:https://support.zabbix.com/browse/ZBX-20350
  - POC/EXP:https://forum.90sec.com/t/topic/2045
  - 批量利用工具:https://github.com/Mr-xn/cve-2022-23131

- CVE-2022-23134 Zabbix未授权访问到接管后台
  - 漏洞影响版本:**5.4.0 - 5.4.8、6.0.0 - 6.0.0beta1**
  - 漏洞介绍及修复建议:https://support.zabbix.com/browse/ZBX-20384
  - POC/EXP:https://www.ctfiot.com/27130.html

### 向日葵
- CNVD-2022-10270 向日葵个人版for Windows命令执行漏洞
  - 漏洞影响版本:**Windows个人版 11.0.0.33**
  - 漏洞介绍及修复建议:https://www.cnvd.org.cn/flaw/show/CNVD-2022-10270
  - POC/EXP:https://chowdera.com/2022/02/202202251725051373.html
  - 批量利用工具:https://github.com/Ryze-T/CNVD-2022-10270-LPE

### 钉钉办公软件
- 钉钉办公软件远程命令执行漏洞
  - 漏洞影响版本:**6.3.5**
  - 漏洞介绍及修复建议:https://www.cfanz.cn/resource/detail/nAvwlDExjLADB
  - POC/EXP:https://github.com/crazy0x70/dingtalk-RCE

# 说明
**1.以下漏洞均为作者收集，请勿用于非法渠道，POC/EXP使用与作者本人无关**

**2.其中涉及的影响版本都是包含该版本(如1.0.1-2.0.0表示1.0.1和2.0.2版本都受影响)**

**3.里面的POC/EXP和利用脚本均为作者在网上查找，并没有一一进行验证，不能保证每一个POC/EXP或脚本都没有错误**

# 项目列表

- [提权辅助工具](#提权辅助工具)
- [Windows本地提权漏洞](#Windows本地提权漏洞)
- [Linux本地提权漏洞](#Linux本地提权漏洞)

# 漏洞列表

### 提权辅助工具
- Windows/Linux辅助提权工具汇总:https://cloud.tencent.com/developer/article/1944250?from=15425
- Windows提权辅助工具:https://i.hacking8.com/tiquan
- Linux提权扫描脚本:https://github.com/mzet-/linux-exploit-suggester
- Linux提权命令一览表:https://gtfobins.github.io

### Linux本地提权漏洞
- CVE-2022-0847 Linux Dirty Pipe本地提权漏洞
  - 漏洞影响版本**5.8 <= Linux 内核版本 < 5.16.11 / 5.15.25 / 5.10.102**
  - 漏洞介绍及修复建议:https://mp.weixin.qq.com/s/b8DmtIerXuoC7f3nqaOVIw
  - POC/EXP:https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit

- CVE-2021-43267 Linux kernel TIPC任意代码执行权限提升漏洞
  - 漏洞影响版本:**5.10 < Linux Kernel < 5.15**
  - 漏洞介绍及修复建议:https://www.secrss.com/articles/36572
  - POC/EXP:https://github.com/ohnonoyesyes/CVE-2021-43267

- CVE-2021-42008 Linux kernel越界写入权限提升漏洞
  - 漏洞影响版本:**2.1.94 <= Linux kernel <= 5.13.3**
  - 漏洞介绍及修复建议:https://www.jianshu.com/p/d4d2874ed356
  - POC/EXP:https://github.com/0xdevil/CVE-2021-42008

- CVE-2021-33909 Linux kernel本地提权漏洞
  - 漏洞影响版本:**3.16 <= Linux kernel <= 5.13.3**
  - 漏洞介绍及修复建议:https://www.4hou.com/posts/lXGJ
  - POC/EXP:https://github.com/Liang2580/CVE-2021-33909

- CVE-2021-31440 Linux内核eBPF提权漏洞
  - 漏洞影响版本:**Linux kernel >= 5.7**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/242567
  - POC/EXP:暂无

- CVE-2021-22555 Linux Netfilter越界写提权漏洞
  - 漏洞影响版本:**2.6.19-rc1 <= Linux Kernel**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/251515
  - POC/EXP:https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/exploit.c

- CVE-2021-4034 pkexec本地提权漏洞
  - 漏洞影响版本:**大多数主流linux系统均受影响**
  - 漏洞介绍及修复建议:https://cert.360.cn/warning/detail?id=25d7a6ec96c91ca4e4238fd10da2c778
  - POC/EXP:https://github.com/EstamelGG/CVE-2021-4032-NoGCC/releases/tag/v1.0

- CVE-2021-3560 Polkit权限提升漏洞
  - 漏洞影响版本:**RHEL8 ｜ Fedora21及更高版本 ｜ Debiantesting("bullseye") ｜ Ubuntu20.04**
  - 漏洞介绍及修复建议:https://www.freebuf.com/vuls/281081.html
  - POC/EXP:https://github.com/Almorabea/Polkit-exploit

- CVE-2021-3493 Linux kernel本地提权漏洞
  - 漏洞影响版本:**Ubuntu 20.10 | Ubuntu 20.04 LTS | Ubuntu 18.04 LTS | Ubuntu 16.04 LTS | Ubuntu 14.04 ESM**
  - 漏洞介绍及修复建议:https://mp.weixin.qq.com/s/D2LM7OUvbiNYXfPG-peU3A
  - POC/EXP:https://github.com/briskets/CVE-2021-3493

- CVE-2021-3490 Linux_LPE_eBPF本地提权漏洞
  - 漏洞影响版本:**Ubuntu 20.10(Groovy Gorilla)kernels 5.8.0(25.26)-5.8.0(52.58) | Ubuntu 21.04(Hirsute Hippo)5.11.0(16.17)**
  - 漏洞介绍及修复建议:https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
  - POC/EXP:https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490

- CVE-2021-3156 Sudo堆缓冲区溢出提权漏洞
  - 漏洞影响版本:**Sudo 1.8.2-1.8.31p2 | Sudo 1.9.0-1.9.5p1**
  - 漏洞介绍及修复建议:https://www.freebuf.com/vuls/270839.html
  - POC/EXP:https://haxx.in/CVE-2021-3156_nss_poc_ubuntu.tar.gz

- CVE-2020-27194 Linux内核eBPF权限提升漏洞
  - 漏洞影响版本:**5.7 <= Linux kernel <= 5.8.14**
  - 漏洞介绍及修复建议:http://official.hnyongxu.com:417/mobile/SecurityIncidents/124.html
  - POC/EXP:https://github.com/xmzyshypnc/CVE-2020-27194

- CVE-2020-8835 eBPF任意读写提权漏洞
  - 漏洞影响版本:**5.4.7 <= Linux Kernel < 5.4.x | 5.5.0 <= Linux Kernel**
  - 漏洞介绍及修复建议:https://nvd.nist.gov/vuln/detail/CVE-2020-8835
  - POC/EXP:https://github.com/zilong3033/CVE-2020-8835

- CVE-2019-15666 xfrm UAF 8字节写NULL提权漏洞
  - 漏洞影响版本:**Linux Kernel < 5.0.19**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/253234
  - POC/EXP:https://github.com/bsauce/kernel-exploit-factory/blob/main/CVE-2019-15666/exp.c

- CVE-2019-14287 sudo权限绕过提权漏洞
  - 漏洞影响版本:**sudo < 1.8.28**
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1553933
  - POC/EXP:https://github.com/n0w4n/CVE-2019-14287

- CVE-2019-13272 Linux本地内核提权漏洞
  - 漏洞影响版本:**Linux Kernel < 5.1.17**
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1528508
  - POC/EXP:https://github.com/bcoles/kernel-exploits/tree/master/CVE-2019-13272

- CVE-2019-7304 Ubuntu Linux权限提升漏洞
  - 漏洞影响版本:**Ubuntu 18.10 | Ubuntu 18.04 LTS | Ubuntu 16.04 LTS | Ubuntu 14.04 LTS**
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1512126
  - POC/EXP:https://github.com/initstring/dirty_sock

- CVE-2018-1000001 Glibc本地提权漏洞
  - 漏洞影响版本:**glibc <= 2.26**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/205197
  - POC/EXP:https://github.com/5H311-1NJ3C706/local-root-exploits/tree/master/linux/CVE-2018-1000001

- CVE-2018-18955 Linux内核提权漏洞
  - 漏洞影响版本:**4.15.x < Linux Kernel < 4.19.2**
  - 漏洞介绍及修复建议:https://www.freebuf.com/vuls/197122.html
  - POC/EXP:https://www.exploit-db.com/exploits/45886

- CVE-2018-17182 Linux 内核VMA-UAF提权漏洞
  - 漏洞影响版本:**Linux kernel <= 4.18.8**
  - 漏洞介绍及修复建议:https://www.cnblogs.com/backlion/p/9729914.html
  - POC/EXP:https://github.com/backlion/CVE-2018-17182

- CVE-2018-5333 kernel exploit空指针引用提权漏洞
  - 漏洞影响版本:**Linux kernel <= 4.14.13**
  - 漏洞介绍及修复建议:https://blog.csdn.net/panhewu9919/article/details/119153052
  - POC/EXP:https://github.com/bcoles/kernel-exploits/blob/master/CVE-2018-5333/cve-2018-5333.c

- CVE-2017-1000405 Huge Dirty COW本地提权漏洞
  - 漏洞影响版本:**2.6.38 <= Linux kernel <= 4.14**
  - 漏洞介绍及修复建议:https://www.freebuf.com/column/203162.html
  - POC/EXP:https://github.com/bindecy/HugeDirtyCowPOC

- CVE-2017-1000367 Sudo本地提权漏洞
  - 漏洞影响版本:**1.8.6p7 <= Sudo <= 1.8.20**
  - 漏洞介绍及修复建议:https://help.aliyun.com/document_detail/54251.html
  - POC/EXP:https://github.com/lexfo/cve-2017-11176/blob/master/cve-2017-11176.c

- CVE–2017–1000253 Linux PIE/stack内存破坏本地提权漏洞
  - 漏洞影响版本:**CentOS < CentOS 7(1708版本) ｜ Red Hat < Red Hat Enterprise Linux 7(7.4) | CentOS 6.x | Red Hat 7.x**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/86939
  - POC/EXP:暂无

- CVE-2017-1000112 UDP报文处理不一致导致堆溢出提权漏洞
  - 漏洞影响版本:**Linux kernel <= 4.12.6
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1396155
  - POC/EXP:https://github.com/ol0273st-s/CVE-2017-1000112-Adpated/blob/master/Exploit.c

- CVE-2017-16995 Linux Kernel本地提权漏洞
  - 漏洞影响版本:**4.14 <= Linux Kernel <= 4.4**
  - 漏洞介绍及修复建议:https://zhuanlan.zhihu.com/p/35247850
  - POC/EXP:https://github.com/Al1ex/CVE-2017-16995

- CVE-2017-16939 Linux Kernel本地权限提升漏洞
  - 漏洞影响版本:**2.6.28 < Linux kernel < 4.14**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/87327
  - POC/EXP:https://github.com/SecWiki/linux-kernel-exploits/tree/master/2017/CVE-2017-16939

- CVE-2017-11176 Linux kernel UAF本地权限提升漏洞
  - 漏洞影响版本:**Linux kernel < 4.11.9**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/247073
  - POC/EXP:https://github.com/lexfo/cve-2017-11176/blob/master/cve-2017-11176.c

- CVE-2017-7308 Linux内核提权漏洞
  - 漏洞影响版本:**Linux kernel < 4.10.6**
  - 漏洞介绍及修复建议:https://www.77169.net/html/161809.html
  - POC/EXP:https://www.exploit-db.com/exploits/41994

- CVE-2017-6074 Linux kernel DCCP double-free权限提升漏洞
  - 漏洞影响版本:**Linux kernel > 2.6.18**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/253478
  - POC/EXP:https://www.exploit-db.com/exploits/41458

- CVE-2017-5123 null任意地址写权限提升漏洞
  - 漏洞影响版本:**Linux v4.14-rc5**
  - 漏洞介绍及修复建议:https://bsauce.github.io/2021/05/31/CVE-2017-5123/#kernel-exploitcve-2017-5123-null%E4%BB%BB%E6%84%8F%E5%9C%B0%E5%9D%80%E5%86%99%E6%BC%8F%E6%B4%9E
  - POC/EXP:https://github.com/nongiach/CVE/tree/master/CVE-2017-5123/exploit

- CVE-2016-9793 本地提权漏洞
  - 漏洞影响版本:**3.11 <= Linux kernel <= 4.8.13**
  - 漏洞介绍及修复建议:http://cn-sec.com/archives/278454.html
  - POC/EXP:https://www.exploit-db.com/exploits/41995

- CVE-2016-5195 Linux脏牛本地提权漏洞
  - 漏洞影响版本:**Linux kernel >= 2.6.22**
  - 漏洞介绍及修复建议:https://www.jianshu.com/p/df72d1ee1e3e
  - POC/EXP:https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c

- CVE-2016-4557 Linux-raspi2本地提权漏洞
  - 漏洞影响版本:**Linux kernel <= 4.5.4**
  - 漏洞介绍及修复建议:https://vuldb.com/zh/?id.87604
  - POC/EXP:https://www.exploit-db.com/exploits/39772

- CVE-2016-0728 Linux内核提权漏洞
  - 漏洞影响版本:**Linux kernel >= 3.8.x**
  - 漏洞介绍及修复建议:https://www.anquanke.com/post/id/83342
  - POC/EXP:https://github.com/SecWiki/linux-kernel-exploits/blob/master/2016/CVE-2016-0728/cve-2016-0728.c

- Linux Suid提权漏洞
  - 漏洞影响版本:**配置了特殊权限的系统**
  - 漏洞介绍及修复建议:https://www.freebuf.com/articles/web/272617.html
  - POC/EXP:https://jlkl.github.io/2020/01/27/Web_15/
  - 批量利用工具:https://github.com/Jewel591/suidcheck

- Linux Sudo提权漏洞
  - 漏洞影响版本:**配置了sudoer文件特殊权限的系统**
  - 漏洞介绍及修复建议:https://cloud.tencent.com/developer/article/1708368
  - POC/EXP:https://developer.aliyun.com/article/654362

---
title: Linux SGX Demo
longtitle: 2019-02-20-Linux SGX Demo
key: article-2019-02-20-linux-sgx-demo
tags: [linux, SGX, 可信计算, 安全]
excerpt_separator: <!--more-->
published: true
---

{%- capture resource -%}
{{site.resource}}{{page.key}}
{% endcapture %}

本文通过分析改编 sgx-sdk 提供的 Sample Enclave 初步学习 Intel SGX 技术的使用方法, 从开发者的角度简单学习 SGX 代码如何编写. 需要读者对 GNUmake, linux 下程序编译有基本了解.
<!--more-->

资料来源: 
+ [Sgx Sdk Sev Reference](https://software.intel.com/en-us/sgx-sdk-dev-reference) <sup> [4](#seealso4)</sup>
+ [Linux-Intel-SGX-Developer-Guide](https://software.intel.com/sites/default/files/managed/33/70/intel-sgx-developer-guide.pdf) <sup>[5](#seealso5)</sup>. 

研究的代码来自于 sgxsdk/Samplecode/SampleEnclave, 但经过了修改和简化, 去掉了大部分的 edl 语法功能, 只实现一个最简单的 Enclave 和其使用环境. 本文使用的代码可以于 
[SGX-demo](https://github.com/yah-yuan/SGX-demo) 下载.

如果有任何问题, 欢迎评论或与我联系. 同样, 笔者也刚接触 SGX, 文中有很多谬误和认识不足, 希望读者可以不吝指正.

# 什么是 SGX

(这个问题上网就可以了解.)

SGX 是 Intel 于 2014 年提出的一种基于 CPU 可信基的可信计算技术, 应用该技术的 app 可以让敏感代码受保护地运行于危险的软硬件环境中, 同时 Intel 也给开发者提供了基于 SGX 开发的安全运行库和开发工具用于应用开发. 截至目前 SGX 并未见到大规模商用而停留于学界研究.

与传统的 TPM/TPM2.0 信任几乎整个计算机硬件不同, Intel SGX 的信任面非常小, 它只信任 CPU 本身, 可以说是对可信计算概念的进一步抽象, 因此给予攻击者的攻击面非常小(但侧信道攻击的攻击面却相应变大了). 在不考虑侧信道和程序漏洞的情况下, 使用 SGX 的 Enclave 内部是十分安全的, 原因是其运行环境完全不为其他应用所见(包括 root 用户), 故即使在云环境下也可以保证数据代码的安全.

SGX 也提供了 "密封" "迁移" 的功能. 该功能同样完全由 CPU 实现, 可以将 Enclave 中的敏感数据加密并存储在计算机硬盘中. 在较高安全级别的加密中, 密封的数据可以对进行解密加密的 CPU 进行认证, 验证其是否与加密者是同一 CPU, 保证除该 CPU 外的任意 CPU 均不能获取秘密(即使攻击者获知密钥), 意味着攻击本地数据的攻击者只能使用本机进行加密, 攻击难度大大增加.

然而 SGX 也存在严重的问题. 其一是开发复杂, 对 Enclave 内外进行严格区分, 互相之间的调用只能通过特定的 CPU 指令. 为简化开发, Intel 提供了一系列软件, 如 sgx_sign, sgx_edger8r, sgx-gdb 等. 另一就是侧信道攻击, 几乎所有的侧信道攻击都可以用于 SGX 攻击, 该题目也是目前学界研究的热门.

SGX 首先被应用于 windows 平台, 但 Intel 后续于 2016 年开发了 Linux 版本, 给研究者提供了便利. 本文基于 Linux, 不谈 SGX 繁复的技术目标和内部实现, 从**开发者的角度**学习使用 SGX, 这无疑和传统的软件开发不同, 因为开发者除了了解抽象的软件结构外, 还需要对 SGX 的工作原理和代码规范有更深的理解, 这是必须的(不然要 SGX 做什么呢 XD).

# 几个 SGX 的概念

与本文相关的几个概念

## Enclave

Enclave, 即是 SGX 保证安全的核心, 是一块由 CPU 管理的内存, 这块内存保存了敏感代码和数据, 只能由 CPU 调用和运行并不被外部资源共享. 因此当程序运行于 Enclave 内部时称其为可信的(trusted), 而运行与 Enclave 外部时称其为不可信的(untrusted). 

## EDL

即 Enclave Defination Language. 因为 Enclave 不同于共享的资源, 其与外部不可信内容的交互需要特定的规则进行限定. Intel SGX 给出了一种语言来抽象地描述 Enclave 内部函数的调用权限和数据的出入方式, 并通过 sgx_edger8r 翻译成一系列可编译的代码.

EDL 提出了一种"边规则"(edge routine) 的概念. 一个 edge routine 即是运行于 Enclave 内部或外部的函数和它们与 Enclave 外部或内部的调用关系的总称.

## SGX library

由于运行于 Enclave 中的代码不信任计算机中的其他资源--包括了共享库, SGX 有其自己的一套标准库系统, 提供了常见的库函数实现, 在编译好的 sgxsdk 中,函数原型存在于 include 文件中, 其中可被 Enclave 内代码调用的函数又存在于 include/tlibc 中, 64 位系统下的库文件存在于 lib64 中. 值得注意的是, 被 Enclave 调用的库全都是 .a 的档案文件, 都是静态库, 即 Enclave 的代码一旦被编译就无法更改(这也造成了一个 Enclave 比一般的程序大的多).

SGX 系统运行时被分为两部分, 不可信的称为 untrusted Run Time System(uRTS), 负责加载管理 Enclave 和处理 Enclave 函数的调用和返回; 可信的 Enclave 称为 trusted Run Time System (tRTS), 负责接收调用处理并返回, 同时也管理自身程序.

## ECall and OCall

"Enclave Call" 是 Enclave 内部程序的接口函数.

"Out Call" 是可由 Enclave 内部代码调用的外部函数接口.

## Trusted Bridge 和 Trusted Proxy

一个抽象概念. 由于 enclave 和外部环境是完全隔离的, 因此他们中间的参数传递(尤其是指针)必须经过验证, 这一机制被称为 Trusted Bridge 和 Trusted Proxy. 代码实现上, 有 sgx_edger8r 产生的代码的功能就是 Trusted Bridge 和 Trusted Proxy.

有区别吗? 简单的说, Bridge 检测 ECall 的参数, proxy 检测 OCall 的参数. 可以参考 [Intel 工程师的回答](https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/707015).

## SGX 应用

由于 CPU 资源少, 可用的 Enclave 资源不多, 对开发者来说运行于 Enclave 中的代码应该是重要的,敏感的,精简的, 而一个完整的 SGX 应用是 trusted code 和 untrusted code 与它们之间交互代码的总称, SGX 的安全问题也往往取决与 untrusted code, 因此抛开 untrusted code 只分析 Enclave 是不明智的.

现在我们开始分析这个简单的 Enclave 的应用.

# 运行环境

我的测试环境是 ubuntu 18.04 以及 [sgxsdk](https://01.org/intel-software-guard-extensions/downloads) version 2.3.1. 这个版本的 sdk 安装已经十分简单, 运行 .bin 包即可.

请务必在测试的 shell 中**导出环境变量**.

```sh
$ export environment
```

下载测试 repo :
```sh
$ git clone https://github.com/yah-yuan/SGX-demo
$ cd enclave-demo/
```

测试代码的结构为:

```
SGX-demo/
├── App       # 不可信的代码
│   ├── app_demo.c
│   ├── Makefile
│   └── sgx_error.c
├── Enclave   # 可信的代码
│   ├── enclave.c
│   ├── enclave.config.xml
│   ├── enclave.pem
│   └── Makefile
├── include   # 一些头文件
│   ├── BuildEnv.mk
│   └── enclave.edl
├── Makefile
└── README.md
```

<script id="asciicast-jVA1UMax8GQQt00WHxnkMKeqD" src="https://asciinema.org/a/jVA1UMax8GQQt00WHxnkMKeqD.js" async></script>

编译方法:
```sh
$ make
```

我们的测试内容在仿真(SIM)模式下进行. 具有硬件支持的测试者可以在 make 中加上 SGX_MODE=HW 定义进行真实硬件代码的编译(可能需要调整 Makefile)

```sh
$ make SGX_MODE=HW
```

输出结果为
```sh
$ ./app_demo
I am the SGX secret
Info: demo enclave successfully returned.
```
清除构建内容开始分析
```
make clean
```
# Enclave

首先分析 ./Enclave 下的内容.

Enclave 的目标是生成一个共享目标文件(.so). 在进入 ./Enclave 后 make :
```sh
$ cd Enclave
$ make
```

make 留下的 log 如下:

```
[GEN]  =>  enclave_t.h enclave_t.c
[CC] enclave.c => enclave.o
[CC]  enclave_t.c => enclave_t.o
[LD] enclave.o =>  enclave.so
[SIGN] =>  ../enclave.signed.so
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
The required memory is 4038656B.
Succeed.
```

编译 Enclave 会在项目根目录生成一个 enclave.signed.so 文件, 该文件既是将被 untrusted code 调用的 Enclave.

## 功能实现: enclave.c
```c
char * secret = "I am the SGX secret\n";
char buff[100]; // used to be copied outside of Enclave

void e_call_print_secret() {
    snprintf(buff,100,"%s",secret);
    ocall_print_string(buff);
}
```
这个 Enclave 实现的功能非常简单, Enclave 中有一个 secret string, 当外部应用调用 e_call_print_secret() 时 Enclave 则会打印这个 secret. 然而 printf() 并没有被 SGX 提供的安全库包含(和不可信的显存设备交换数据本身就是不安全的), 因此, 我们使用 SGX 提供的 snprintf() 将格式化后的字符串保存在 buff 中, 调用一个 untrusted code 提供的 OCall 来实现字符串的打印. 更简单的说就是 e_call_print_secret() 事实上是进行了一次 Enclave 内部到外部的内存拷贝.

## Step1: 从 .edl 入手生成 enclave_t.h 和 enclave_t.c

./include/enclave.edl 是这样进行描述的.

```C
enclave {

    trusted {
        public void e_call_print_secret();
    };

    untrusted {
        void ocall_print_string([in, string] const char * str);
    };
};
```

可信代码中提供一个 void e_call_print_secret() 函数(见 Enclave/enclave.c), 该函数可以被不可信代码调用(public), 没有参数;

不可信代码中提供一个 void ocall_print_string(const char * str) 函数(见 App/app_demo.c), 该函数需要把一个字符串(string)从 Enclave 复制到 OCall 所在内存(in).

这两个例子说明了 .edl 是如何声明 Enclave 结构的, 基本有以下要素: 提供什么函数, 接口是什么, 权限如何(能否被不可信部分调用?), 如何传参(是否复制参数? 是否将改变后的参数复制到原始内存中?参数内存大小?), 以及 edl 中将要用到的 struct. 更为详细的 .edl 语法规则可以参考[补充说明:EDL常用语法](#using-edl).

只有抽象的代码是不够的, 抽象描述不能被编译器解释. sgx_edger8r 工具根据 enclave.edl 生成接口函数和其头文件. _t意味着该文件被 trusted Enclave 使用, 为其提供**调用不可信代码**和**返回到可信代码**的接口 (因为每次调用和返回都要被 Bridge 或 Proxy 处理, 而不是直接调用目标函数).

## Step2: 编译链接为 Enclave

目前 Enclave 中需要编译的源文件有:enclave.c 和enclave_t.c

需要注意的是, 在 Enclave/Makefile 中我们定义了**不使用**系统默认的头文件和链接库:
```mk
Crypto_Library_Name := sgx_tcrypto
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(INCLUDE_DIR)
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections \
	-fdata-sections -fstack-protector-strong
Enclave_C_Flags += $(Enclave_Include_Paths) -nostdinc
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined \
	-nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) \
	-l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections
```
前文提到 SGX 在运行 Enclave 时有不同于系统的安全库. sgxsdk/include/tlibc 中提供了这些安全的头文件, 其中包括 stdlib.h, stdio.h, unistd.h 等常用头. 对应的, 在链接时我们也不能使用外部系统的链接库(不安全的动态链接库甚至会被打桩)(我没有测试过 SGX 硬件是否会验证非 SGX 安全库文件, 但应该有相关的验证方式), 可以看到在 ./include/MakeEnv.mk 中定义了要使用的链接库 Trts_Library_Name 和 SGX_LIBRARY_PATH, 前者用于 Enclave 运行时, 后者用于和不可信区域交互.

Makefile 中有复杂的编译链接选项, 但都是必须的. 其中运行时库必须完整被链接(whole-archive), 其他库则可以有连接器决定需要的符号. -nostdlib 和 -nostartfiles 十分重要, 前者保证链接器不使用系统库, 后者则让链接的目标不需要入口函数.

由此, 我们得出了一个enclave.so. 但是仅有这个目标文件是不足以让 CPU 验证该 enclave 的, 直接运行会提示 Error Code 0x2009: The metadata is incorrect. 我们还需要对 enclave.so进行签名.

## Step3: 签名 Enclave

签名的作用是保证 Enclave 不被篡改. 签名根据 Enclave 的二进制内容进行, 一旦被签名, 任何的篡改都将被 SGX 加载硬件检测从而拒绝加载到 CPU.

SGX 提供了两种签名方式: 一步签名和两步签名. 两部签名需要将你的 Enclave 送至签名机构进行认证, 这通常用于向用户分发 release 版本的 SGX 程序. 我们将使用 debug 版本的一步签名.

签名需使用一个.pem的 rsa 私钥. 测试代码中已经提供了一个私钥, 但你仍然可以使用 openssl 工具生成一个自己的私钥.

sgxsdk 提供了其签名工具 sgx_sign, 该工具, 进行一步签名时可直接使用如下代码:
```sh
$ sgx_sign sign -key enclave.pem -enclave enclave.so -out enclave.signed.so -config Enclave.config.xml
```
其中, Enclave.config.xml 声明了一些用户对 Enclave 的内存布局和高级特性定义的参数, 如最大栈空间, 最大堆空间等. SGX 也提供了 sgx_emmt 工具用于度量代码需要的空间大小, 使用它可以节省 Enclave 空间.

最终, ./Enclave/Makefile 生成了 ./enclave.signed.so, 它可以被加载程序所调用.

# 不可信的代码

编译不可信代码:
```sh
$ cd App
$ make
```
输出结果为:
```sh
[GEN] enclave_u.h enclave_u.c
[CC] app_demo.c => app_demo.o
[CC] enclave_u.c => enclave_u.o
[CC] sgx_error.c => sgx_error.o
[LD] app_demo.o => ../app_demo
```

## 功能实现: app_demo.c

不可信的代码负责加载 enclave 和调用 ecall.

初始化函数是由用户定义的 initialize_enclave(void), 该函数进行如下操作:

* 找到 enclave.token.so

* 用户目录下创建一个 token 文件, 如果已经存在的话则读取 token.

* 调用由 uRTS 库提供的 sgx_create_enclave() 函数创建一个 enclave.

* 如果 token 被更新, 则将更新后的 token 保存.

成功执行 initialize_enclave 后, app_demo 调用 e_call_print_secret(eid), 参数 eid 唯一指定了刚才创建的 enclave.

结束测试前应该销毁已加载的 enclave, 调用 sgx_destroy_enclave(eid).

## token 的作用

当一个 Enclave 第一次试图在 CPU 上加载时, Intel Launch Enclave(LE) 会对该 enclave 进行验证<sup>[3](#seealso3)</sup>, 验证内容即是对 Enclave 进行的签名, LE 将检测 enclave 的完整性和合法性, 对验证通过的 enclave 发放一个 token, 这样在下次加载时使用已验证的 token 将加快加载速度.

## Step1: 生成 enclave_u.c 和 enclave_u.h

与 Enclave 中的代码一样, untrusted code 需要通往 SGX 的函数接口 ECalls 和声明提供给 Enclave 的函数接口 OCalls. 

## Step2: 编译

可以从 Makefile 中看到, 对于不可信代码的编译没有再使用新的库, 开发者可以随意使用库和头. 其中一个搜索路径 sgxsdk/include 中包含了与 sgx 相关的头文件 sgx_urts.h 和 enclave_u.h 等, 对应的库是 sgxsdk/lib64 下的 libsgx_urts_sim.so 和 libsgx_uae_service_sim.so. 注意到这两个库是动态库. 

编译生成的 app_demo 是 demo 程序的入口.

# 补充说明

## 代码规范

本文只涉及 SGX 开发最简单的部分. 具体开发安全的代码需要开发人员有良好的安全代码素质. 在编写 sgx 应用时应注意以下方面:
* 任何 Enclave 中的 bug 或不安全代码都会影响整个 Enclave 的安全性, 应着力提升 Enclave 内部代码质量. 
  
* 在编写 Enclave 代码时应额外注意函数接口的设计, 因为 untrusted code 的输入是不可信的(可能会在 Encalve 中进行栈溢出等操作).
  
* 由于 OCalls 运行于不可信部分, Enclave 代码不能保证 Ocall的函数按照期望去执行. 应当尽量少使用 OCalls, 将代码的执行权限交到不可信的环境中是危险的.
  
* 任何人都可以调用 Enclave, 因此攻击者可能会在计算机上执行恶意的 Enclave 去攻击其他的 Enclave(在云环境中尤为明显). 事实上这是可能的, 研究者已经对此有所研究: [_Malware Guard Extension: Using SGX to Conceal Cache Attacks_<sup>[2]</sup>](#seealso2).
  
* 开发者应当谨慎对待引用的对象. SGX 的 ECall 在使用引用变量时并不立刻复制它在原始内存中的值,而是在检查完成后才使用这一引用. 因此攻击者可能会在 Enclave 检查过参数后和复制到 enclave 内之前进行引用修改, 产生内存错误的情况.
  
* Enclave 不提供任何侧信道保护, 因此对于侧信道攻击的防范被完全交予开发者. 对于常见的侧信道攻击对 Enclave 内部数据的结构有所要求, 因此可以由此着手减轻侧信道攻击面. 同时, SGX 为 SSL/TSL 提供了安全的版本, 但网络相关的程序更加大了 SGX 侧信道攻击面.

## <span id="using-edl">EDL常用语法

SGX 文档中有对 [EDL 的说明文档](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax), 这里只对重要的部分进行摘录.

### 基本语法

```C
enclave {
    //Include 头文件, 这些头文件在 trust code 和 untrust code 中都会出现
    include "string.h"
    
    //导入其他 edl 文件, 类似于 py 的语法
    from other1.edl import *; //全部导入
    from other2.edl import func1; //选择导入
    
    //此 edl 文件中将要用到的 struct
    struct mysecret {
        char secret[100];
	  };
    
    trusted { // 可信的 enclave
        // 同样可以 include 和 import
          
        // 可信的函数原型
        public void e_call_print_secret();
    };
    
    untrusted { // 不信的代码
        // 同样可以 include 和 import
          
        // 不可信函数原型
        void ocall_print_string([in, string] const char * str);

    };
};
```

一个 edl 中, 除非是用做被导入的 library,则必须至少有一个 trusted 的函数, 作为用于进入enclave 的入口. 同时, 一个预处理后的 edl 文件(即加入了 include 和 import 的内容) 必须至少有一个 public 的函数,否则这个 enclave 将无法进入. 相反, untrusted 部分从来都不是必须的.

函数参数在传递过程中要经过 trusted bridge 并被 trusted proxy 检测. 因此, 在申明函数的参数(尤其是指针)时, 必须说明合法的参数属性.

### 指针

指针参数有以下可选属性:

in, out, user_check, string, wstring, size, count, isptr, readonly

(这里说的指针是 ecall 和 ocall 的参数, 而不是这些函数的返回指针, 这些指针只能被 enclave 和 用户代码所检测.)

使用方括号表示指针属性, 属性之间用逗号隔开.

不支持函数指针.

#### 指针方向

+ [in] 指该指针**传入**函数所在的代码区域. 因此, ecall 的 [in] 指针把数据传入 enclave, ocall 的[in]则将数据传入 untrusted 内存.

+ [out] 与 [in] 相反. 

+ [in] 和 [out] 可以结合作为 [in, out] 使用, 表示该段内存在函数返回后再次传入调用者内存.

+ [usercheck] 属性为 usercheck 的指针不会被 enclave 桥检测, 但指针的内容也不会被复制(那有什么用啊...). 若函数为 ocall, 则指针指向的内存也不可操作.

这是一个 in , out sercheck 在不同函数中的比较:

||ECALL|OCALL|
|--- |--- |--- |
|user_check|Pointer is not checked. Users must perform the check and/or copy.|Pointer is not checked. Users must perform the check and/or copy|
|in|Buffer copied from the application into the enclave. Afterwards, changes will only affect the buffer inside enclave. Safe but slow.|Buffer copied from the enclave to the application. Must be used if pointer points to enclave data.|
|out|Trusted wrapper function will allocate a buffer to be used by the enclave. Upon return, this buffer will be copied to the original buffer.|The untrusted buffer will be copied into the enclave by the trusted wrapper function. Safe but slow.|
|in, out|Combines in and out behavior. Data is copied back and forth.|Same as ECALLs.|

#### 缓冲区长度

缓冲区长度由两方面决定: size, count

+ [size] 这项属性说明了该指针指向数据块的元大小. 如果没有 size 属性, 则默认为当前环境下指针 keyword 的大小. 如某个大小为 64 字节的结构数组的指针, 可以用 [size=64]来表示.

+ [count] 这项属性说明了数据块的数量,默认为 1. 如有 100 个这样的块则可以表示为 [count=100].

size 和 count 属性与指针的方向一起使用, 他们也可以同时存在表示缓冲区的大小为 size * count, 同时, 这两个值可以被设置为函数中的其他参数, e.g.

```C
enclave{
      trusted {
          // 缓冲区大小为 cnt * sizeof(int) 字节
          public void test_count([in, count=cnt] int* ptr, unsigned cnt);
            
          // 缓冲区大小为 cnt * len 字节
          public void test_count_size([in, count=cnt, size=len] int* ptr, unsigned cnt, size_t len);
      };
};
```

#### 字符串类型

String 和 wstring 是特殊的数据属性.

如果一个指针的属性是 String 和 wstring, 则它由 \n 字符或 wchar_t 字符作为终结标志. 因此这两个属性不能与 size 或 count 一起使用. 另外, 这两个个属性不能用于仅有 out 属性的方向中.

### 数组

数组与指针类似, 但没有 size 或 count 属性. 它的大小直接被标记在符号之后:

```C
enclave {
      trusted {
      
          public void test_array([in] int arr[4]);
            
          public void test_array_multi([in] int arr[4][4]);
            
      };
};

```

数组参数不支持 const 关键字, 不支持长度为 0 的数组或者可变数组, 不支持指针数组.

## 数据迁移

即 SGX 提供的 data sealing 功能. 该功能也由 CPU 指令实现, 可能在以后的文章中进行测试学习.

# 参考资料

<span id="seealso1">[1] <https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html> 以及它的中文翻译 <https://www.4hou.com/web/12898.html> . 此文对 SGX 内部构造工作原理进行分析.

<span id="seealso2">[2] Schwarz, Michael, et al. "Malware guard extension: Using SGX to conceal cache attacks." International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment. Springer, Cham, 2017.

<span id="seealso3">[3] <https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/798514>

<span id="seealso4">[4] <https://software.intel.com/en-us/sgx-sdk-dev-reference>

<span id="seealso5">[5] Linux-Intel-SGX-Developer-Guide: <https://software.intel.com/sites/default/files/managed/33/70/intel-sgx-developer-guide.pdf>

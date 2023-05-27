# Yet Another DoIP(YA-DoIP)

本项目是Python3实现跨平台的，完全符合**ISO-13400 (2019)**国际规范的，同步非阻塞IO的，Diagnostic over IP (DoIP)**协议栈**，协议栈部分可以实现DoIP数据的收发 && 解析等。搭配本项目附赠的上位机client的demo，你可以进一步获得对于UDS协议（**ISO14229**）的支持，从而实现：
1. 车载以太网ECU的诊断/刷写
2. DoIP转DoCAN ECU的诊断/刷写
3. 多路DoIP ECU的并行刷写
4. 甚至可以搭配DoIP server节点的能力实现**并行诊断/刷写**DoCAN ECU们:smirk:
5. 即插即用，搭配Wireshark你甚至可以抛弃贵重的设备，诸如Vector 5640等

本项目遵循MIT LISCENCE，如果各位业界大佬们有兴趣，可以直接通过本仓库提PR，也可邮箱联系我chenxiao9609@foxmail.com。

## 1. 初衷

本人在OEM车厂~~练习两年半~~，由于工作相关性我想要实现一个DoIP的上位机，在全网寻找一番后，发现仅有Jacob Schaer在github上实现了[同步阻塞IO版本的协议栈](https://github.com/jacobschaer/python-doipclient/)，对于实现一个简易的上位机来说已经够用了，但是个人认为**扩展性不够强且实现并行功能的话比较困难**。

在没有现成轮子的情况下，我决定从头实现一个可重入的同步非阻塞IO版本的DoIP协议栈，并搭配其实现了可以**并行刷写的上位机**:smirk:。同时，我也希望大家能够和BMW一样，能够积极推进在智能汽车领域的开源氛围。

## 2. 项目介绍

本项目实现的是一个轻量级的完全符合**ISO-13400 (2019)**国际规范的同步非阻塞IO版本的DoIP协议栈，支持一个stack接入多个client，采用Python3编写。YA-DoIP非常简单易用，整个stack部分的核心代码甚至只有不到200行，~~我是说真的，我不是培训班广告~~。client部分的话由于server端刷写的知识产权和保密原因，我暂时不会开源全部，只会开放一个demo供大家参考，但是相信我，大家可以通过我提供的demo根据各个OEM制定的标准进行愉快的玩耍了。

针对类似于ISO13400-2中描述的经典拓扑图，你可以实现对不同DoIP node的并行诊断刷写或对DoCAN node的串行诊断刷写。

<div align=center><img src="./.assets/2-ISO13400经典拓扑图.jpg#pic_center" alt="2-ISO13400经典拓扑图" /></div>

针对类似于下图中的树形结构的拓扑图，你可以实现对DoIP node下不同CAN BUS的ECU的并行诊断/刷写，如图中DoCAN Node 1与DoCAN Node 4。

<div align=center><img src="./.assets/3-经典树形拓扑图.jpg" alt="3-经典树形拓扑图" /></div>

~~下面是本项目支持并行刷写的证据：~~

<div align=center><img src="./.assets/1-证据.png" alt="1-证据" /></div>

**项目的各文件说明：**

- stack.py: DoIP协议栈的核心部分，支持DoIP数据的收发与解析，当前我已经实现了TCP部分的核心（包括Routing Activation、Diagnostic Message等），~~由于我懒~~UDP部分还没有实现，但是已经不影响整体stack的使用。
- messages.py: DoIP协议栈的底层消息格式的文件，是我从Jacob Schaer的项目原始获得并进行了一些微调。用Jacob Schaer的原话来说“*Quoted descriptions were copied or paraphrased from ISO-13400-2-2019 (E).*”，所以我直接在其基础上进行了复用~~我懒~~，避免了重复的轮子。
- client-demo.py：搭配stack实现的支持并行的demo文件，其中实现了一个基本的DoIPClient的类，你可以通过继承这个类并重构自己的相应函数来实现功能。我仅给各位专家提供一个可行的思路，下文进行详细解释，大家完全可以自由发挥。

## 3. 食用方法

完整的client与stack配合的使用方法可以查看client-demo.py，其中stack对象与client对象是一对多的映射关系，client中需有一个master client负责DoIP节点的路由激活等工作。

```python
# initialization
master_client = DoIPClient(target_address=0x1111)
master_client.daemon = True
client = DoIPClient(target_address=0x2222)
client.daemon = True

stack = DoIPStack(client_ip_address="127.0.0.1", server_ip_address="127.0.0.1")
stack.daemon = True
test_present_timer = RepeatTimer(interval=2.5, function=tester_present, args=(client, ))
test_present_timer.daemon = True
master_client._doip_stack = stack
client._doip_stack = stack

# register all the clients
stack.register_master_client(0x1111, client=master_client)
stack.register_client(0x2222, client=client)

master_client.process_software_package()
client.process_software_package()

if stack.connect_edge_node(timeout=0.05) == 0:
    stack._is_edge_node_connected = True
    stack.start()
    master_client.start()
    # maybe you need some condition check here for the next two lines
    client.start()
    test_present_timer.start()

    while True:
        time.sleep(5)
        log.info("Main thread tick...")
        if master_client._current_client_running == False:
            test_present_timer.cancel()
            break
else:
    log.error("EDGE NODE connect failed.")
```

每一个client对象都是继承自threading.Thread对象并通过注册函数注册到stack，从而形成stack一对多映射client的关系。实现的时候你可以继承我提供的DoIPClient的对象，重载所有的回调函数即可；你也可以通过修改stack的相关参数，实现你想要的额外功能。You can do what the friendly you want to do, just get the friendly code.

此外，我还在demo中提供了一些有限状态机的建议，如UDS的状态、刷写的状态、消息解析器的状态等，你可以参考我的代码来实现你的上位机。

```python
class UDSState(IntEnum):
    IDLE = 0
    SENT = 1
    PENDING = 2
    POSITIVE_RESPONSE = 3
    NEGATIVE_RESPONSE = 4
    FUNCTIONAL_COLLECTING = 5


class FlashState(IntEnum):
    IDLE = 0
    EDGE_NODE_ROUTING_ACTIVATE = 1
    F_DEFAULT_SESSION_ON = 2
    # start
    """
        Finite State Machine of ISO 14229 stuff here
    """
    # over
    FLASHED_OK = 3
    FLASHED_FAIL = 4

class Parser:
    def __init__(self):
        self.reset()

    def reset(self):
        self.rx_buffer = bytearray()
        self.protocol_version = 0x00
        self.inverse_version = 0x00
        self.payload_type = 0x0000
        self.payload_length = 0x00000000
        self.payload = bytearray()
        self._state = ParserState.READ_PROTOCOL_VERSION

    def parse(self, data):
        self.rx_buffer += data
        log.debug("parser buffer: 0x{}".format(self.rx_buffer.hex().upper()))
        parsed_list = []

        while len(self.rx_buffer) > 0:
            if self._state == ParserState.READ_PROTOCOL_VERSION:
                self.payload = bytearray()
                if len(self.rx_buffer) >= 1:
                    self.protocol_version = int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_INVERSE_PROTOCOL_VERSION
                else:
                    break
                
            if self._state == ParserState.READ_INVERSE_PROTOCOL_VERSION:
                if len(self.rx_buffer) >= 1:
                    self.inverse_version = int(self.rx_buffer.pop(0))
                    if self.inverse_version != (0xFF ^ self.protocol_version):
                        log.warning("DoIP HEADER: protocol version && inverse version CAN NOT match. Ignoring......")
                    self._state = ParserState.READ_PAYLOAD_TYPE
                else:
                    break
            
            if self._state == ParserState.READ_PAYLOAD_TYPE:
                if len(self.rx_buffer) >= 2:
                    self.payload_type = int(self.rx_buffer.pop(0)) << 8
                    self.payload_type |= int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_PAYLOAD_LENGTH
                else:
                    break
            
            if self._state == ParserState.READ_PAYLOAD_LENGTH:
                if len(self.rx_buffer) >= 4:
                    self.payload_length = int(self.rx_buffer.pop(0)) << 24
                    self.payload_length |= int(self.rx_buffer.pop(0)) << 16
                    self.payload_length |= int(self.rx_buffer.pop(0)) << 8
                    self.payload_length |= int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_PAYLOAD_OPEN
                else:
                    break

            if self._state == ParserState.READ_PAYLOAD_OPEN:
                if len(self.rx_buffer) < self.payload_length:
                    log.info("Current parser wants more data......")
                    break
                else:
                    self.payload += self.rx_buffer[:self.payload_length]
                    self.rx_buffer = self.rx_buffer[self.payload_length:]
                    self._state = ParserState.READ_PROTOCOL_VERSION
                    log.debug("payload_type: {}".format(payload_type_to_message_dict[self.payload_type]))
                    log.debug("After parse, payload: 0x{}".format(self.payload.hex().upper()))
                    parsed_list.append(payload_type_to_message_dict[self.payload_type].unpack(self.payload, self.payload_length))
        
        return parsed_list
```

stack与client之间的纽带是相应的发送函数的回调函数，在回调函数中可以执行相应的threading.Event()的操作，该变量相当于一个semaphore。当然，你也可以完全重构我的代码，推导重来。

另外，我还实现了一个普通的定时器类，你也可以继承该类，实现诸如定时发送tester present等功能。

```python
class RepeatTimer(Timer):
    def run(self):
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)

def tester_present(client):
    message = DiagnosticMessage(source_address=0x0001, target_address=0x0002, user_data=bytes.fromhex("3E80"))
    if client._doip_stack._is_edge_node_connected:
        client._doip_send(message)
        log.info("tester present")
```

## 4. 运行环境
理论上你可以在所有支持Python3的平台运行，我使用的是Python3.9.9 32-bit版本。

## 5. 待办项

1. UDP部分
2. TCP剩余一小部分
3. 单元测试部分
4. 也许可以改一改stack发送队列
5. 也许实现一个DoIP Server Simulator

## 6. 值得一提的事

过程中给我的一些便利以及帮助，如:

- 日本友人实现的带图形界面的[DoIP模拟器](https://github.com/hiro-telecom-engineer/python-doip)，对于新接触的人来说可以非常直观的感受到对于DoIP流程的交互
- 好用的现成库，如ECU文件解析的库`hexrec`，如xml文件解析的库`xml`，也如Python自带的强大log工具`logging`
- 强大的网络工具`wireshark`
- 来自华为上研所我的[PigB队友](https://gitee.com/zhaoyingzhuo)~~陪我打游戏~~的鼓励与支持
- 如果你觉得好用，联系我，我可以请你喝一杯咖啡:coffee:
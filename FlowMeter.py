"""
   读取pcap文件，并生成网络流
"""

from scapy.layers.inet import IP

from multiprocessing import Process

from scapy.all import *
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

import numpy as np


class BasicPacketInfo:
    def __init__(self, src, dst, sport, dport, protocol, timestamp, payload):
        self.__id = 1
        self.__src = src
        self.__dst = dst
        self.__sport = sport
        self.__dport = dport
        self.__protocol = protocol
        self.__timestamp = timestamp
        self.__payload = payload

        self.generateFlowId()

        # Flags (8/8)
        self.__flagFIN = False
        self.__flagPSH = False
        self.__flagURG = False
        self.__flagECE = False
        self.__flagSYN = False
        self.__flagACK = False
        self.__flagCWR = False
        self.__flagRST = False

        # Additional details (3/3)
        self.__TCPWindow = -1

    def generateFlowId(self):
        forward = True
        if self.__src > self.__dst:
            forward = False
        if forward:
            self.__flowId = self.__src + "-" + self.__dst + "-" + str(self.__sport) + "-" + str(
                self.__dport) + "-" + str(self.__protocol)
        else:
            self.__flowId = self.__dst + "-" + self.__src + "-" + str(self.__dport) + "-" + str(
                self.__sport) + "-" + str(self.__protocol)
        return self.__flowId

    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src

    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst

    def getSrcPort(self):
        return self.__sport

    def setSrcPort(self, srcPort):
        self.__srcPort = srcPort

    def getDstPort(self):
        return self.__dport

    def setDstPort(self, dstPort):
        self.__dstPort = dstPort

    def getProtocol(self):
        return self.__protocol

    def setProtocol(self, protocol):
        self.__protocol = protocol

    def getTimestamp(self):
        return self.__timestamp

    def setTimestamp(self, ts):
        self.__timestamp = ts

    def setFlowId(self, flowId):
        self.__flowId = flowId

    def getFlowId(self):
        return self.__flowId

    def isForwardPacket(self, src):
        return self.__src == src

    def getPayload(self):
        return self.__payload

    def setPayload(self, payload):
        self.__payload = payload

    def hasFlagFIN(self):
        return self.__flagFIN

    def setFlagFIN(self):
        self.__flagFIN = True

    def hasFlagPSH(self):
        return self.__flagPSH

    def setFlagPSH(self):
        self.__flagPSH = True

    def hasFlagURG(self):
        return self.__flagURG

    def setFlagURG(self):
        self.__flagURG = True

    def hasFlagECE(self):
        return self.__flagECE

    def setFlagSYN(self):
        self.__flagECE = True

    def hasFlagSYN(self):
        return self.__flagSYN

    def setFlagSYN(self):
        self.__flagSYN = True

    def hasFlagACK(self):
        return self.__flagACK

    def setFlagFin(self):
        self.__flagACK = True

    def hasFlagCWR(self):
        return self.__flagCWR

    def setFlagCWR(self):
        self.__flagCWR = True

    def hasFlagRST(self):
        return self.__flagRST

    def setFlagRST(self):
        self.__flagRST = True

    def getTCPWindow(self):
        return self.__TCPWindow

    def setTCPWindow(self, TCPWindow):
        self.__TCPWindow = TCPWindow

    def setFlags(self, flagByte):

        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

        if flagByte & FIN:
            self.__flagFIN = True
        if flagByte & SYN:
            self.__flagSYN = True
        if flagByte & RST:
            self.__flagRST = True
        if flagByte & PSH:
            self.__flagPSH = True
        if flagByte & ACK:
            self.__flagACK = True
        if flagByte & URG:
            self.__flagURG = True
        if flagByte & ECE:
            self.__flagECE = True
        if flagByte & CWR:
            self.__flagCWR = True

class BasicFlow:
    def __init__(self,packInfo):
      self.firstPacket(packInfo)

    def firstPacket(self, packetInfo:BasicPacketInfo):
        self.__src=packetInfo.getSrc()
        self.__dst=packetInfo.getDst()
        self.__sport=packetInfo.getSrcPort()
        self.__dport=packetInfo.getDstPort()
        self.__protocol=packetInfo.getProtocol()

        self.__startTime=packetInfo.getTimestamp()
        self.__endTime=packetInfo.getTimestamp()

        self.__packetSequence=[]
        self.__packetSequence.append(packetInfo.getPayload())

        self.__flowId = packetInfo.getFlowId()

    def getFlowStartTime(self):
        return self.__startTime

    def getFlowEndTime(self):
        return self.__endTime

    def addPacket(self,packetInfo:BasicPacketInfo):
        currentTimestamp = packetInfo.getTimestamp()
        # 双向流
        self.__endTime=currentTimestamp
        self.__packetSequence.append(packetInfo.getPayload())

    def dumpFlowBasedFeatures(self, fileObject,max_packet,max_bytes):
        min_packets=1
        if(len(self.__packetSequence)>=min_packets):
            dump = ""
            sep = ","
            dump += str(self.__startTime) + sep
            dump += str(self.__endTime) + sep
            dump += self.__src + sep
            dump += self.__dst + sep
            dump += self.__sport + sep
            dump += self.__dport + sep
            dump += self.__protocol + sep
            packet_str = ""
            for i in range(max_packet):
                if (i < len(self.__packetSequence)):
                    temp_str = sep.join(str(j) for j in self.__packetSequence[i])
                    packet_str += temp_str + ","
                else:
                    temp_arr = np.ones(shape=(max_bytes, 1), dtype=np.uint8)*-2
                    temp_arr = temp_arr.reshape(-1)
                    temp_str = sep.join(str(j) for j in temp_arr)
                    packet_str += temp_str + ","
            dump += packet_str
            dump = dump.strip(sep)

            fileObject.write(dump)
            fileObject.write('\n')


class FlowGenerator:
    def __init__(self,flowTimeout,activityTimeout,output_file_object,maxPackets,maxBytes):
        self.__flowTimeout = flowTimeout
        self.__activityTimeout = activityTimeout

        self.init()

        self.__fileObject = output_file_object

        self.maxPackets=maxPackets
        self.maxBytes=maxBytes

    def init(self):
        self.__flowCount = 0
        self.__currentFlows = {}
        self.__finishedFlowCount = 0


    def addPacket(self,packetInfo):
        currentTimestamp = packetInfo.getTimestamp()

        if packetInfo.getFlowId() in self.__currentFlows:
            flow = self.__currentFlows[packetInfo.getFlowId()]
            if (currentTimestamp - flow.getFlowStartTime() > self.__flowTimeout or currentTimestamp-flow.getFlowEndTime() > self.__activityTimeout):
                self.__currentFlows[packetInfo.getFlowId()].dumpFlowBasedFeatures(self.__fileObject,self.maxPackets,self.maxBytes)
                del self.__currentFlows[packetInfo.getFlowId()]
                self.__currentFlows[packetInfo.getFlowId()] = BasicFlow(packetInfo)
            elif packetInfo.hasFlagFIN() or packetInfo.hasFlagRST():
                flow.addPacket(packetInfo)
                self.__currentFlows[packetInfo.getFlowId()].dumpFlowBasedFeatures(self.__fileObject,self.maxPackets,self.maxBytes)
                del self.__currentFlows[packetInfo.getFlowId()]
            else:
                flow.addPacket(packetInfo)
                self.__currentFlows[packetInfo.getFlowId()] = flow
        else:
            self.__flowCount += 1
            self.__currentFlows[packetInfo.getFlowId()] = BasicFlow(packetInfo)

    def flush_flows(self):
        print("A total of {} flows generated".format(self.__flowCount))
        for (key, val) in self.__currentFlows.items():
            val.dumpFlowBasedFeatures(self.__fileObject,self.maxPackets,self.maxBytes)

"""
   预处理部分
   单个包处理
   将单个进行处理，形成满足要求的长度为 256 的 0-1 Array
"""
# 移除Ether header
def remove_eth(packet):
    if packet.haslayer("Ether"):
        return packet['Ether'].payload
    return packet

def mask_port(p):
    if(p.haslayer(TCP) or p.haslayer(UDP)):
        p.sport=0
        p.dport=0
    return p

# mask ip addr
def mask_ip(packet):
    if packet.haslayer("IP"):
        packet['IP'].src = '0.0.0.0'
        packet['IP'].dst = '0.0.0.0'
    return packet

# pad UDP header from 8 bytes to 20 bytes
def pad_udp(packet):
    if packet.haslayer('UDP'):
        # get layers after udp
        layer_after = packet[UDP].payload.copy()
        # Padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet
    return packet

# first transform packet to array,then matrix
def packet_to_matrix(p,max_len):
    # np.frombuffer :创建np.array对象,e.g. array([1, 2, 3], dtype=uint8)
    # raw(packet) : b'\xff\xff\xff
    #arr = np.frombuffer(raw(p)[: max_len], dtype= np.uint8)# / 255
    arr = np.frombuffer(p[Raw].load[: max_len], dtype=np.uint8)  # / 255
    if len(arr) < max_len:
        # s = [1,2,3]
        # np.pad(s, (1,2), 'constant')
        # (1,2)表示前面填充1个，后面填充2个 ==> [0,1,2,3,0,0]
        # 若 s 为多维array,填充宽度为 [(1,2),(0,2), ...]，每个()代表 s 的第几维
        pad = np.ones(shape=(max_len - len(arr),), dtype=np.uint8) * -1
        arr = np.concatenate([arr, pad])  # np.pad(arr, (0, max_len - len(arr)),'constant',constant_values=-1)

    # 返回稀疏存储结果，减少内存开销
    #arr = sparse.csr_matrix(arr)
    return arr

#处理vlan
def process_802q(p):
    if(p.haslayer(Dot1Q)):
        return p['Dot1Q'].payload
    return p
# 处理packet
def process_packet(p,max_len):
    p = remove_eth(p)
    while(p.haslayer(Dot1Q)):
        p=process_802q(p)
    #print(p.haslayer(Dot1Q))
    p = mask_ip(p)
    p = mask_port(p)
    p = pad_udp(p)
    #print(p.summary())
    #print(len(raw(p)))
    print(len(p[Raw].load))
    print(p[Raw].load)
    p = packet_to_matrix(p,max_len)
    return p

class FlowMeter():
    def __init__(self, input_file, output_file_object, flowTimeout, activityTimeout):
        self.__input_file = input_file
        self.__output_file_object = output_file_object
        self.__flow_timeout = flowTimeout
        self.__activity_timeout = activityTimeout
        self.__flowGen = None

        self.__minPackets=16
        self.__minBytes=16*16

    def flush_flows(self):
        self.__flowGen.flush_flows()


    def capture_file(self):
        flow_log={}
        count=0
        self.__flowGen = FlowGenerator(self.__flow_timeout, self.__activity_timeout, self.__output_file_object,self.__minPackets,self.__minBytes)

        packetInfo = None

        pcap_reader = PcapReader(self.__input_file)

        for packet in pcap_reader:
            try:
                if (packet.haslayer(IP))  and (packet.haslayer(TCP) or packet.haslayer(UDP)) and packet.haslayer(Raw) :#and packet.haslayer(Raw)
                    if not (packet.haslayer(NTP) or packet.haslayer(DNS) or packet.sport == 5353 or packet.dport == 5353): #or packet.haslayer(DNS)
                        timestamp = int((packet.time) * 1000)  # 13位时间戳
                        srcip = packet[IP].src
                        dstip = packet[IP].dst
                        proto = str(packet[IP].proto)

                        sport = str(packet.sport)
                        dport = str(packet.dport)


                        flag_FIN= False
                        flag_RST= False
                        if packet.haslayer(TCP):
                            if packet[TCP].flags & FIN:
                                flag_FIN= True
                            if packet[TCP].flags & RST:
                                flag_RST=True

                        payload_data = process_packet(packet, self.__minBytes)

                        #payload_data = payload_data.reshape(16, 16)  # 完成payload数据提取

                        packetInfo=BasicPacketInfo(srcip,dstip,sport,dport,proto,timestamp,payload_data) # 数据

                        if(flag_FIN):
                            packetInfo.setFlagFIN()
                        if(flag_RST):
                            packetInfo.setFlagRST()

                        self.__flowGen.addPacket(packetInfo)
            except:
                traceback.print_exc(file=sys.stdout)
                logging.error('Biflow extraction failed', exc_info=True)
                continue
        self.__flowGen.flush_flows()


# 获取pcap列表
def get_pcap_list(input_dir):
    pcap_list=[]
    for root,directory,files in os.walk(input_dir):
        for filename in files:
            name,suf=os.path.splitext(filename)
            if suf=='.pcap' or suf=='.pcapng':
                pcap_list.append(os.path.join(root,filename))
    return pcap_list

def split_pcap_1(pcap_list,output_dir):
    for pcap_path in pcap_list:
        folder_path, pcap_file = os.path.split(pcap_path)
        file_name = pcap_file + '.txt'
        print(file_name)
        save_csv_path = os.path.join(output_dir, file_name)
        output_file_object = open(save_csv_path, "w")
        fm = FlowMeter(pcap_path, output_file_object, 120000000, 5000000)
        fm.capture_file()


def split_pcap(input_dir,output_dir):
    pcap_list=get_pcap_list(input_dir)

    print('开始流量分割')

    num_process=3

    split_pcap_list=[]
    if(len(pcap_list)<=num_process):
        split_pcap_list.append(pcap_list)
    else:
        size = int(len(pcap_list) / num_process)
        for i in range(0,int(len(pcap_list)+1),size):
            c=pcap_list[i:i+size]
            if c!=[]:
                split_pcap_list.append(c)

    process_list=[]

    for i in range(len(split_pcap_list)):
        t=Process(target=split_pcap_1,args=(split_pcap_list[i],output_dir))
        process_list.append(t)

    for t in process_list:
        t.start()

    for t in process_list:
        t.join()

    print('流量分割完成')

    return True

if __name__ == '__main__':
    cic_dir = "E:\\All_Pcaps\\pcap_new"
    cic_save_dir = 'F:\\test_802.q'
    split_pcap(cic_dir,cic_save_dir)









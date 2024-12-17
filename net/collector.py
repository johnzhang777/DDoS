 # log_packet in collector.py
import threading
from pyshark import LiveCapture
from config.config import Config
from collections import deque
from ryu.lib.packet import packet
from pyof.v0x04.common.header import Header
from pyof.v0x04.symmetric.experimenter import ExperimenterHeader
from scapy.all import Ether, Raw, sendp
from pyof.v0x04.asynchronous.packet_in import PacketIn, PacketInReason
from pyof.v0x04.common.flow_match import Match, OxmTLV, OxmOfbMatchField, OxmClass
from pyof.foundation.basic_types import UBInt32, UBInt16, UBInt8, UBInt64, BinaryData
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6, ether_types, tcp
from ryu.lib.packet.ethernet import ethernet as Ethernet
from ryu.lib.packet.icmpv6 import icmpv6 as ICMPv6
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketIn, OFPMatch
from ryu.ofproto.ofproto_v1_3 import OFPR_ACTION
from pyof.v0x04.asynchronous.packet_in import PacketIn, PacketInReason
from pyof.v0x04.common.flow_match import Match


import asyncio
import uuid
import socket
import json

# global lock for thread-safe printing
output_lock = threading.Lock()

class PacketCollector:
    def __init__(self):
        self.live_captures = {}
        self.threads = []
        self.stop_event = threading.Event()
        self.count = 0
        self.config = Config()
        self.window_size = self.config.get_window_size()
        self.packet_window = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('127.0.0.1', 6653))

    def start_capture(self, interfaces):
        # for interface in interfaces:
        #     # create a new thread to handle each interface's capture
        #     thread = threading.Thread(target=self.sniff_continuously, args=(interface,))
        #     self.threads.append(thread)
        #     thread.start()
         self.sniff_continuously(interfaces)


    def stop_capture(self):
        self.stop_event.set()
        for interface, capture in self.live_captures.items():
            asyncio.run(capture.close())
        self.live_captures.clear()


    def sniff_continuously(self, interface):
        try:
            # create a live capture object
            capture = LiveCapture(interface=interface)

            if not isinstance(interface, list):
                interface = [interface]
            self.live_captures[interface[0]] = capture

            for packet in capture.sniff_continuously():
                try:
                    if self.stop_event.is_set():
                        # capture.close()
                        break
                    packet_info = self.parse_packet(packet)
                    if packet_info is None:
                        continue
                    self.packet_window.append(packet_info)
                    # self.log_packet(packet_info, interface)
                    if len(self.packet_window) == self.window_size:
                        # TODO: 通过构造 Experimenter 消息，实现交换机向控制器发送相关数据
                        # self.send_experimenter_message(self.sock, self.packet_window)
                        # self.send_packet_in(self.sock, self.packet_window)
                        self.send_packet_in()
                        self.packet_window.clear()  # 清空窗口以准备接收下一批数据包
                    self.count += 1
                except AttributeError as e:
                    print(f"Error parsing packet: {e}")
        except KeyboardInterrupt:
            print(f"Stopping capture on interface: {interface}")
            self.stop_capture()
        finally:
            self.stop_capture()

    def send_experimenter_message(self, sock, data):
        data = '123'
        binary_data = json.dumps(data).encode('utf-8')
        experimenter_msg = ExperimenterHeader(
            experimenter = 0x0BCD,
            exp_type = 0xEFDD,
            data=binary_data
        )
        
        #  发送experimenter消息包
        sock.send(experimenter_msg.pack())
        # print(experimenter_msg.pack())
        # print(experimenter_msg.is_valid())
        # print("Experimenter message sent successfully")
    
    def create_ipv6_icmp_packet(self):
        # 构造 Ethernet 头部
        eth = ethernet.ethernet(
            dst='00:00:00:00:00:02',  # 目标 MAC 地址
            src='00:00:00:00:00:01',  # 源 MAC 地址
            ethertype=ether_types.ETH_TYPE_IPV6  # IPv6 类型
        )

        # 构造 IPv6 头部
        ipv6_hdr = ipv6.ipv6(
            src='2001:db8::1',  # 源 IPv6 地址
            dst='2001:db8::2',  # 目标 IPv6 地址
            nxt=58,  # ICMPv6 协议号
            hop_limit=64
        )

        # 构造 ICMPv6 Echo 请求
        icmpv6_hdr = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_ECHO_REQUEST,  # ICMPv6 类型：Echo 请求
            code=0,
            csum=0,  # 校验和会自动计算
            data=icmpv6.echo(id_=1, seq=1, data=b'Hello, World!')
        )

        # 构造完整的包
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(ipv6_hdr)
        pkt.add_protocol(icmpv6_hdr)
        pkt.serialize()  # 自动计算校验和并序列化数据
        # print(bytes(pkt.data))

        return bytes(pkt.data)
    
    def create_ipv6_http_response_packet(self):
        # 构造 HTTP 响应
        http_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "Custom Data Here"  # 自定义数据
        ).encode('utf-8')

        # 构造 TCP 段 (假设我们已经在已有的连接上)
        src_port = 80     # 源端口号 (HTTP服务器)
        dst_port = 12345  # 目标端口号 (客户端)
        seq = 1           # 序列号 (这里简化为1，实际应用中需要根据实际情况设置)
        ack = 1           # 确认号 (这里简化为1，实际应用中需要根据实际情况设置)
        offset = 5        # 数据偏移
        flags = tcp.TCP_ACK  # ACK 标志位，表示确认收到之前的数据
        tcp_hdr = tcp.tcp(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            offset=offset,
            bits=flags,
            window_size=65535,
            csum=0,       # 校验和会自动计算
            urgent=0,
            option=None
        )

        # 构造 IPv6 头部
        ipv6_hdr = ipv6.ipv6(
            src='2001:db8::2',  # 源 IPv6 地址 (服务器地址)
            dst='2001:db8::1',  # 目标 IPv6 地址 (客户端地址)
            nxt=6,              # TCP 协议号
            hop_limit=64
        )

        # 构造 Ethernet 头部
        eth = ethernet.ethernet(
            dst='00:00:00:00:00:01',  # 目标 MAC 地址 (客户端MAC)
            src='00:00:00:00:00:02',  # 源 MAC 地址 (服务器MAC)
            ethertype=ether_types.ETH_TYPE_IPV6  # IPv6 类型
        )

        # 构造完整的包
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(ipv6_hdr)
        pkt.add_protocol(tcp_hdr)
        pkt.add_protocol(http_response)
        pkt.serialize()  # 自动计算校验和并序列化数据

        return bytes(pkt.data)


    def send_packet_in(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 6653))
        
        address = ('127.0.0.1', 6653)

        # 构造以太网帧
        # eth_frame = Ethernet()
        # eth_frame.source = '00:00:00:00:00:01'
        # eth_frame.destination = '00:00:00:00:00:02'
        # eth_frame.ethertype = 0x86dd  # IPv6
        ipv6_packet_bytes = self.create_ipv6_http_response_packet()
        # eth_frame.data = ipv6_packet_bytes
        # eth_frame_bytes = eth_frame.pack()

        
        # 创建一个 PacketIn 消息
        packet_in = PacketIn(
            xid=1,
            buffer_id=0xffffffff,  # 表示没有缓冲区，数据包需要被包含在 data 中
            total_len=len(ipv6_packet_bytes),
            reason=PacketInReason.OFPR_ACTION,
            table_id=0,
            cookie=0,
            match=Match(),
            data=ipv6_packet_bytes  # 这里填入实际的数据包内容
        )
        print(packet_in.pack())
        sock.send(packet_in.pack())
        sock.close()

    def handle_packet_out(self, custom_data):
        # 收到数据并回复
        response_data = b"Hello, RYU! Received: " + custom_data
        #随便构建回复消息
        packet = Ether() / Raw(load=response_data)
        # 发给控制器
        sendp(packet, iface=self.name)

    def parse_packet(self, packet):
        packet_info = {
            'packet_length': None,
            'ttl': None,
            'source_mac': None,
            'destination_mac': None,
            'source_ip': None,
            'destination_ip': None,
            'protocol': None,
            'source_port': None,
            'destination_port': None,
            'tcp_flags': None,
            # 'http_request_method': None,
            # 'http_request_uri': None,
            'icmp_type': None,
            'icmp_code': None,
        }

        packet_info['packet_length'] = packet.length

        if 'eth' in packet:
            packet_info['source_mac'] = packet.eth.src
            packet_info['destination_mac'] = packet.eth.dst

        if 'ip' in packet:
            packet_info['source_ip'] = packet.ip.src
            packet_info['destination_ip'] = packet.ip.dst
            packet_info['protocol'] = packet.ip.proto
            packet_info['ttl'] = packet.ip.ttl
        else:
            return None

        if 'tcp' in packet:
            packet_info['source_port'] = packet.tcp.srcport
            packet_info['destination_port'] = packet.tcp.dstport
            packet_info['tcp_flags'] = packet.tcp.flags

        if 'udp' in packet:
            packet_info['source_port'] = packet.udp.srcport
            packet_info['destination_port'] = packet.udp.dstport

        # if 'http' in packet:
        #     packet_info['http_request_method'] = packet.http.request_method
        #     packet_info['http_request_uri'] = packet.http.request_full_uri

        if 'icmp' in packet:
            packet_info['icmp_type'] = packet.icmp.type
            packet_info['icmp_code'] = packet.icmp.code

        return packet_info

    def log_packet(self, packet_info, interface):
        with output_lock:
            print(f"Packet captured on {interface}:")
            print(packet_info)
            print(self.count)
            print('------------------')

# import threading
# from pyshark import LiveCapture

# class PacketCollector:
#     def __init__(self, switch):
#         self.switch = switch
#         self.live_captures = {}
#         self.threads = []

#     def start_capture(self, interfaces):
#         # for interface in interfaces:
#         #     # create a new thread to handle each interface's capture
#         #     thread = threading.Thread(target=self.sniff_continuously, args=(interface,))
#         #     self.threads.append(thread)
#         #     thread.start()
#         self.sniff_continuously(interfaces)

#     def stop_capture(self):
#         # stop all pyshark captures
#         for interface, capture in self.live_captures.items():
#             capture.close()
#         self.live_captures.clear()

#         # wait for all threads to finish
#         for thread in self.threads:
#             thread.join()
#         self.threads.clear()

#     def sniff_continuously(self, interface):
#         try:
#             # create a live capture object
#             capture = LiveCapture(interface=interface)
#             self.live_captures[interface] = capture

#             for packet in capture.sniff_continuously():
#                 try:
#                     # parse and print packet details
#                     packet_info = self.parse_packet(packet)
#                     # use the switch's log_packet method
#                     self.switch.log_packet(packet_info, interface)
#                 except AttributeError as e:
#                     print(f"Error parsing packet: {e}")
#         except KeyboardInterrupt:
#             print(f"Stopping capture on interface: {interface}")
#             capture.close()

#     def parse_packet(self, packet):
#         packet_info = []
#         if 'IP' in packet:
#             packet_info.append(f"Source IP: {packet.ip.src}")
#             packet_info.append(f"Destination IP: {packet.ip.dst}")

#         if 'TCP' in packet:
#             packet_info.append(f"Source Port: {packet.tcp.srcport}")
#             packet_info.append(f"Destination Port: {packet.tcp.dstport}")
#             packet_info.append(f"TCP Flags: {packet.tcp.flags}")

#         if 'UDP' in packet:
#             packet_info.append(f"Source Port: {packet.udp.srcport}")
#             packet_info.append(f"Destination Port: {packet.udp.dstport}")

#         if 'HTTP' in packet:
#             packet_info.append(f"HTTP Request Method: {packet.http.request_method}")
#             packet_info.append(f"HTTP Request URI: {packet.http.request_full_uri}")

#         if 'ICMP' in packet:
#             packet_info.append(f"ICMP Type: {packet.icmp.type}")
#             packet_info.append(f"ICMP Code: {packet.icmp.code}")

#             if hasattr(packet.icmp, 'echo'):
#                 packet_info.append(f"ICMP Echo (Ping) ID: {packet.icmp.echo.id}")
#                 packet_info.append(f"ICMP Echo (Ping) Seq: {packet.icmp.echo.seq}")

#         return "\n".join(packet_info)
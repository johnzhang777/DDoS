 # log_packet in collector.py
import threading
from pyshark import LiveCapture
from config.config import Config
from collections import deque
from mininet.log import info
import asyncio
import nest_asyncio

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
        self.packet_window = deque(maxlen=self.window_size)

    def start_capture(self, interfaces):
        # for interface in interfaces:
        #     # create a new thread to handle each interface's capture
        #     thread = threading.Thread(target=self.sniff_continuously, args=(interface,))
        #     self.threads.append(thread)
        #     thread.start()
         self.sniff_continuously(interfaces)


    def stop_capture(self):
        self.stop_event.set()
        print(self.live_captures)
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
                    self.log_packet(packet_info, interface)
                    if len(self.packet_window) == self.window_size:
                        # TODO: 处理窗口数据
                        self.packet_window.clear()  # 清空窗口以准备接收下一批数据包
                    self.count += 1
                except AttributeError as e:
                    print(f"Error parsing packet: {e}")
        except KeyboardInterrupt:
            print(f"Stopping capture on interface: {interface}")
            self.stop_capture()
        finally:
            self.stop_capture()

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
 # log_packet in collector.py
import threading
from pyshark import LiveCapture
from config.config import Config
import asyncio
import socket
import json
import re
import traceback
import logging

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
        self.server_ip, self.server_port = self.config.get_server()  
        self.client_socket = None
        self.logger = logging.getLogger(__name__)

    def start_capture(self, interfaces):
        self.connect_to_server()
        self.sniff_continuously(interfaces)

    def stop_capture(self):
        self.stop_event.set()
        print(self.live_captures)
        for interface, capture in self.live_captures.items():
            asyncio.run(capture.close())
        self.live_captures.clear()
        self.disconnect_from_server()

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
        except Exception as e:
            print(f"Failed to connect to server: {e}")

    def disconnect_from_server(self):
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
            print("Disconnected from server.")

    def sniff_continuously(self, interface):
        try:
            capture = LiveCapture(interface=interface)

            if not isinstance(interface, list):
                interface = [interface]
            self.live_captures[interface[0]] = capture

            for packet in capture.sniff_continuously():
                try:
                    if self.stop_event.is_set():
                        break
                    packet_info = self.parse_packet(packet)
                    if packet_info is None:
                        continue
                    self.packet_window.append(packet_info)
                    if len(self.packet_window) == self.window_size:
                        self.send_data_to_server(self.packet_window, interface)
                        self.packet_window.clear()
                    self.count += 1
                except AttributeError as e:
                    print(f"Error parsing packet: {e}")
        except KeyboardInterrupt:
            print(f"Stopping capture on interface: {interface}")
            self.stop_capture()
        finally:
            self.stop_capture()

    def send_data_to_server(self, packet_window, interface):
        if not self.client_socket:
            print("Not connected to server.")
            return

        try:
            packet_window_json = json.dumps({
                "switch": interface[0][:2],
                "packets_info": packet_window
            })  # 将数据封装为 JSON 格式
            packet_bytes = packet_window_json.encode()  # 转换为字节流

            # 发送数据的长度（4字节头部表示数据长度）
            data_length = len(packet_bytes)
            self.client_socket.sendall(data_length.to_bytes(4, byteorder='big'))  

            # 分块发送大数据
            chunk_size = 1024
            for i in range(0, len(packet_bytes), chunk_size):
                self.client_socket.sendall(packet_bytes[i:i+chunk_size])

            # 接收服务器回复
            response = self.client_socket.recv(1024)
            print(f"Received from server: {response.decode()}")

        except Exception as e:
            print(f"Error while sending data to the server: {e}")
            self.disconnect_from_server()
            self.connect_to_server()  # 尝试重新连接服务器

    def decode_payload(self, payload_str, default="Normal"):
        try:
            if not payload_str.startswith("Normal"):
                payload_str = bytes.fromhex(payload_str.replace(':', '')).decode('utf-8', errors='ignore')
                if not re.search(r"(Normal|Attack)", payload_str):
                    return "Normal"
                match = re.search(r"(\w+)Attack", payload_str)
                if match:
                    return match.group(0)
            return payload_str
        except Exception as e:
            return default

    def parse_packet(self, packet):
        packet_info = {
            'packet_length': None,
            'ttl': None,
            'source_mac': None,
            'destination_mac': None,
            'source_ip': None,
            'destination_ip': None,
            'protocol': None,
            'source_port': {},
            'destination_port': {},
            'flag': None,
            'tcp_flags': None,
            'icmp_type': None,
            'icmp_code': None,
        }

        try:
            payload = None
            packet_info['packet_length'] = getattr(packet, 'length', None)

            if 'eth' in packet:
                packet_info['source_mac'] = packet.eth.src
                packet_info['destination_mac'] = packet.eth.dst

            if 'ip' not in packet:
                packet_info['flag'] = "NoIPProtocol"
                return None

            ip_layer = packet.ip
            packet_info.update({
                'source_ip': ip_layer.src,
                'destination_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl
            })

            if 'tcp' in packet:
                tcp_layer = packet.tcp
                packet_info['source_port']['tcp'] = tcp_layer.srcport
                packet_info['destination_port']['tcp'] = tcp_layer.dstport
                packet_info['tcp_flags'] = tcp_layer.flags
                payload = getattr(tcp_layer, 'payload', 'NormalTCPTraffic')
                payload = self.decode_payload(payload, "Normal")

            if 'udp' in packet:
                udp_layer = packet.udp
                packet_info['source_port']['udp'] = udp_layer.srcport
                packet_info['destination_port']['udp'] = udp_layer.dstport
                payload = getattr(packet.data, 'data', 'NormalUDPTraffic')
                payload = self.decode_payload(payload, "Normal")

            if 'icmp' in packet:
                icmp_layer = packet.icmp
                packet_info['icmp_type'] = icmp_layer.type
                packet_info['icmp_code'] = icmp_layer.code
                payload = getattr(icmp_layer, 'data', 'NormalICMPTraffic')
                payload = self.decode_payload(payload, "Normal")

            packet_info['flag'] = payload or "Normal"

        except AttributeError as ae:
            print(f"AttributeError while parsing packet: {ae}")
            packet_info['flag'] = f"AttributeError: {str(ae)}"
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
            print(traceback.format_exc())
            packet_info['flag'] = f"UnexpectedError: {str(e)}"

        # print(packet_info['flag'])
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
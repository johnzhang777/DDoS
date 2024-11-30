import asyncio
import threading
from pyshark import LiveCapture

class PacketCollector:
    def __init__(self):
        self.live_captures = {}

    def start_capture(self, interface):
        # 指定要监听的网络接口
        print(f"Capturing on interface: {interface}")

        # 创建一个实时捕获对象
        capture = LiveCapture(interface=interface)

        # 启动一个新的线程来处理捕获的数据包
        capture_thread = threading.Thread(target=self.sniff_continuous, args=(capture,))
        capture_thread.daemon = True
        capture_thread.start()
        # self.sniff_continuous(capture)

        # 保存捕获对象以便后续停止
        self.live_captures[interface] = capture

    def stop_capture(self):
        # 停止所有 pyshark 实时捕获线程
        for interface, capture in self.live_captures.items():
            capture.close()
        self.live_captures.clear()

    def sniff_continuous(self, capture):
        try:
            for packet in capture.sniff_continuously():
                try:
                    print("Packet captured:")
                    # print('Packet:', packet)
                    
                    # 解析并打印数据包的详细内容
                    if 'IP' in packet:
                        print(f"Source IP: {packet.ip.src}")
                        print(f"Destination IP: {packet.ip.dst}")
                    
                    if 'TCP' in packet:
                        print(f"Source Port: {packet.tcp.srcport}")
                        print(f"Destination Port: {packet.tcp.dstport}")
                        print(f"TCP Flags: {packet.tcp.flags}")
                    
                    if 'UDP' in packet:
                        print(f"Source Port: {packet.udp.srcport}")
                        print(f"Destination Port: {packet.udp.dstport}")
                    
                    if 'HTTP' in packet:
                        print(f"HTTP Request Method: {packet.http.request_method}")
                        print(f"HTTP Request URI: {packet.http.request_full_uri}")

                    # 添加对ICMP数据包的处理
                    if 'ICMP' in packet:
                        print(f"ICMP Type: {packet.icmp.type}")
                        print(f"ICMP Code: {packet.icmp.code}")
                        
                        # 检查是否是ICMP Echo (Ping)请求或回复
                        if hasattr(packet.icmp, 'echo'):
                            print(f"ICMP Echo (Ping) ID: {packet.icmp.echo.id}")
                            print(f"ICMP Echo (Ping) Seq: {packet.icmp.echo.seq}")
                    
                    # 可以继续添加其他协议的解析
                    # 例如 DNS, SSL/TLS 等
                    
                    print('---')
                
                except AttributeError as e:
                    # 处理可能的属性错误
                    print(f"Error parsing packet: {e}")
        except KeyboardInterrupt:
            print(f"Stopping capture on interface: {capture.interface}")
            capture.close()
    async def _sniff_continuously(self, capture):
        loop = asyncio.get_event_loop()
        try:
            while True:
                # 使用同步的阻塞方式捕获一个包
                packet = await loop.run_in_executor(None, capture.sniff, 1)
                
                if packet:
                    print("Packet captured:")
                    if 'IP' in packet:
                        print(f"Source IP: {packet.ip.src}")
                        print(f"Destination IP: {packet.ip.dst}")

                    if 'TCP' in packet:
                        print(f"Source Port: {packet.tcp.srcport}")
                        print(f"Destination Port: {packet.tcp.dstport}")
                        print(f"TCP Flags: {packet.tcp.flags}")
                    
                    if 'UDP' in packet:
                        print(f"Source Port: {packet.udp.srcport}")
                        print(f"Destination Port: {packet.udp.dstport}")

                    if 'HTTP' in packet:
                        print(f"HTTP Request Method: {packet.http.request_method}")
                        print(f"HTTP Request URI: {packet.http.request_full_uri}")

                    if 'ICMP' in packet:
                        print(f"ICMP Type: {packet.icmp.type}")
                        print(f"ICMP Code: {packet.icmp.code}")

                    print('---')

        except asyncio.CancelledError:
            print(f"Capture was cancelled.")

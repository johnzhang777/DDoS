from scapy.all import *
import random

class NormalTrafficGenerator:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, packet_count):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_count = packet_count

    def generate(self):
        for _ in range(self.packet_count):
            packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port)
            send(packet, verbose=0)

if __name__ == '__main__':
    # 正常流量参数
    src_ip = '10.0.0.1'  # 源IP地址
    dst_ip = '10.0.0.2'  # 目标IP地址
    src_port = random.randint(1024, 65535)  # 随机源端口
    dst_port = 80  # 目标端口，例如HTTP
    packet_count = 10  # 发送的包数量

    normal_traffic = NormalTrafficGenerator(src_ip, dst_ip, src_port, dst_port, packet_count)
    normal_traffic.generate()

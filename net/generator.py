from scapy.all import *
from scapy.layers.inet import *
import time

class Generator:
    def __init__(self):
        # self.src_ip = src_ip
        # self.dst_ip = dst_ip
        # self.src_port = src_port
        # self.dst_port = dst_port
        # self.attack_duration = attack_duration  # 攻击持续时间（秒）
        # self.packet_rate = packet_rate  # 每秒发送的包数量
        # self.packet_count = attack_duration * packet_rate
        pass

    def send_packet(self, src_ips, dst_ips, src_ports, dst_ports, duration, rate):
        for src_ip, dst_ip, src_port, dst_port in zip(src_ips, dst_ips, src_ports, dst_ports):
            for _ in range(duration * rate):
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
                # 计算每个包的发送间隔（秒）
                interval = 1 / rate
                print(f"Sending packet from {src_ip} to {dst_ip}")
                time.sleep(interval)
                # start_time = time.time()
                # while (time.time() - start_time) < duration:
                #     print(f"Sending packet from {src_ip} to {dst_ip}")
                #     time.sleep(interval)
                #     continue
                #     # 发送数据包
                #     send(packet, verbose=False)
                #     # 等待指定的间隔时间
                #     time.sleep(interval)

    def normal(self, src_ips, dst_ips, src_ports, dst_ports, duration, rate):
        self.send_packet(src_ips, dst_ips, src_ports, dst_ports, duration, rate)

    def syn_flood(self):
        for _ in range(self.packet_count):
            packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='S')
            send(packet, verbose=0)

    def udp_flood(self):
        for _ in range(self.packet_count):
            packet = IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=self.src_port, dport=self.dst_port)
            send(packet, verbose=0)

    def icmp_flood(self):
        for _ in range(self.packet_count):
            packet = IP(src=self.src_ip, dst=self.dst_ip) / ICMP()
            send(packet, verbose=0)

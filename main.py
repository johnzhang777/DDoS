from net.topo import MyTopo
from net.generator import Generator

if __name__ == '__main__':
    topo = MyTopo()
    topo.run()
    ddos_generator = Generator('10.0.0.2', 80, 10, 100)
    ddos_generator.icmp_flood()
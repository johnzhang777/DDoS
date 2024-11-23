from mininet.topo import Topo
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from config.config import Config

class MyTopo(Topo):
    def __init__(self, *args, **params):
        super().__init__(*args, **params)

        Topo.__init__(self)

    # @override
    def build(self):
        config = Config()


        h1 = self.addHost('h1', ip=config.get_ip('h1'), mac=config.get_mac('h1'))
        h2 = self.addHost('h2', ip=config.get_ip('h2'), mac=config.get_mac('h2'))
        h3 = self.addHost('h3', ip=config.get_ip('h3'), mac=config.get_mac('h3'))

        h4 = self.addHost('h4', ip=config.get_ip('h4'), mac=config.get_mac('h4'))
        h5 = self.addHost('h5', ip=config.get_ip('h5'), mac=config.get_mac('h5'))
        h6 = self.addHost('h6', ip=config.get_ip('h6'), mac=config.get_mac('h6'))

        h7 = self.addHost('h7', ip=config.get_ip('h7'), mac=config.get_mac('h7'))
        h8 = self.addHost('h8', ip=config.get_ip('h8'), mac=config.get_mac('h8'))
        h9 = self.addHost('h9', ip=config.get_ip('h9'), mac=config.get_mac('h9'))

        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3)

        self.addLink(s1, s2)
        self.addLink(s2, s3)

    
    def run(self):
        net = Mininet(topo=self, link=TCLink, controller=RemoteController('c0', ip='127.0.0.1', port=6653))
        net.start()
        # CLI(net)
        return net

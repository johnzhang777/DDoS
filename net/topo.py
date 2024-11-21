from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.net import Mininet
from mininet.cli import CLI

class MyTopo(Topo):
    def __init__(self, *args, **params):
        super().__init__(*args, **params)

        Topo.__init__(self)

    def build(self):

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3)

    
    def run(self):
        net = Mininet(topo=self, controller=RemoteController('c0', ip='127.0.0.1', port=6653))
        net.start()    
        CLI(net)
        net.stop()

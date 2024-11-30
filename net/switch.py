from mininet.node import OVSSwitch
from net.collector import PacketCollector

class CustomSwitch(OVSSwitch):
    def __init__(self, name, **params):
        super(CustomSwitch, self).__init__(name, **params)
        self.collector = PacketCollector()  # 用于存储 Collector 实例
        self.count = 0

    def start(self, *args, **kwargs):
        super(CustomSwitch, self).start(*args, **kwargs)

        for intf in self.intfs.values():
            if intf.name != 'lo':
                print(f"Starting capture on interface: {intf.name}")
                
                if self.collector:
                    self.collector.start_capture(intf.name)

    def stop(self):
        # 停止所有捕获线程
        if self.collector:
            self.collector.stop_capture()
        super(CustomSwitch, self).stop()

    def set_collector(self, collector):
        self.collector = collector
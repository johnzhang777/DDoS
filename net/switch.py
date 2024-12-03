# log_packet not in switch.py (simple structure)
from mininet.node import OVSSwitch
from net.collector import PacketCollector
import threading
import asyncio

class CustomSwitch(OVSSwitch):
    def __init__(self, name, **params):
        super(CustomSwitch, self).__init__(name, **params)
        self.collector = PacketCollector()  # 无需传递 switch 对象
        self.count = 0

    def start(self, *args, **kwargs):
        super(CustomSwitch, self).start(*args, **kwargs)

        interfaces = [intf.name for intf in self.intfs.values() if intf.name != 'lo']

        # 创建线程
        capture = threading.Thread(target=self.collector.start_capture, args=(interfaces,))

        # 启动线程
        capture.start()

    def stop(self):
        # 停止所有捕获线程
        if self.collector:
            self.collector.stop_capture()
        super(CustomSwitch, self).stop()
        return self.collector.count


# from mininet.node import OVSSwitch
# from net.collector import PacketCollector
# import threading

# # Global lock for output
# output_lock = threading.Lock()

# class CustomSwitch(OVSSwitch):
#     def __init__(self, name, **params):
#         super(CustomSwitch, self).__init__(name, **params)
#         self.collector = PacketCollector(self)  # Initialize packet collector
#         self.count = 0

#     def start(self, *args, **kwargs):
#         super(CustomSwitch, self).start(*args, **kwargs)

#         interfaces = [intf.name for intf in self.intfs.values() if intf.name != 'lo']

#         # create a thread to capture packets
#         capture = threading.Thread(target=self.collector.start_capture, args=(interfaces,))

#         capture.start()

#     def stop(self):
#         # stop capturing packets
#         if self.collector:
#             self.collector.stop_capture()
#         super(CustomSwitch, self).stop()

#     def log_packet(self, packet, interface):
#         with output_lock:
#             print(f"Packet captured on {interface}:")
#             print(packet)
#             print('---')




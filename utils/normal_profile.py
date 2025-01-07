import pyshark
import numpy as np
import os
import sys
sys.path.append('./')
print(os.getcwd())

from config.config import Config
from utils.parse import parse_packet
from utils.clean import clean_pkt_info
from utils.entropy import calculate_entropies_for_all_pairs
from collections import defaultdict

class NormalProfile:
    def __init__(self):
        self.capture = pyshark.FileCapture('./resources/2021-10-31-tcp.pcap')
        self.config = Config()
        self.window_size = self.config.get_window_size()

    def group_values_by_key(self, dict_list):
        grouped = defaultdict(list)
        for d in dict_list:
            for key, value in d.items():
                grouped[key].append(value)
        
        # 计算每个键对应的列表的平均值
        averaged_grouped = {'-'.join(key): np.mean(values) for key, values in grouped.items()}
        return averaged_grouped

    def get_normal_proflie(self):
        entropy = []
        packet_info = []
        total_count = 0
        window_count = 0

        # 选取前10000个self.capture数据
        for packet in self.capture:
            if total_count >= 10000:
                break
            parsed_packet_info = parse_packet(packet)
            if parsed_packet_info is None:
                continue
            total_count += 1
            cleaned_packet = clean_pkt_info([parsed_packet_info])
            packet_info.append(cleaned_packet[0])
            window_count += 1
            if window_count >= self.window_size:
                window_count = 0
                entropy.append(calculate_entropies_for_all_pairs(packet_info))
                packet_info = []
        
        entropy = self.group_values_by_key(entropy)
        print(entropy)
        return entropy

            
            
if __name__ == '__main__':
    profile = NormalProfile()
    profile.get_normal_proflie()


# {"packet_length-ttl": 0.8805413854818477, "packet_length-source_ip": 0.910432297601756, "packet_length-destination_ip": 0.9197720729497592, "packet_length-protocol": 0.6104253514000283, "packet_length-source_port": 0.9089701033222819, "packet_length-destination_port": 0.9093792731111171, "packet_length-tcp_flags": 0.6104253514000283, "ttl-source_ip": 0.8993997859079629, "ttl-destination_ip": 0.907130989657589, "ttl-protocol": 0.8667802613569597, "ttl-source_port": 0.9035573593189246, "ttl-destination_port": 0.9005845606347723, "ttl-tcp_flags": 0.8667802613569597, "source_ip-destination_ip": 0.9089536125491463, "source_ip-protocol": 0.8965259421064122, "source_ip-source_port": 0.9052276388477765, "source_ip-destination_port": 0.9043632115305212, "source_ip-tcp_flags": 0.8965259421064122, "destination_ip-protocol": 0.9045112855751625, "destination_ip-source_port": 0.9094374095383435, "destination_ip-destination_port": 0.9099976334381554, "destination_ip-tcp_flags": 0.9045112855751625, "protocol-source_port": 0.8677049903147281, "protocol-destination_port": 0.8687703060303582, "protocol-tcp_flags": 0.0, "source_port-destination_port": 0.9116092443560311, "source_port-tcp_flags": 0.8677049903147281, "destination_port-tcp_flags": 0.8687703060303582}

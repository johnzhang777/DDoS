import math
import numpy as np
from collections import Counter
from typing import List, Dict
from itertools import combinations
from utils.clean import clean_pkt_info
from utils.entropy import calculate_entropies_for_all_pairs, calculate_entropy

class Detector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.columns = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_length", "ttl"]
        self.enouth = False
        self.key_pair = None
        self.normal_profile = {('packet_length', 'ttl'): 0.88, ('packet_length', 'source_ip'): 0.91, ('packet_length', 'destination_ip'): 0.92, ('packet_length', 'protocol'): 0.61, ('packet_length', 'source_port'): 0.91, ('packet_length', 'destination_port'): 0.91, ('ttl', 'source_ip'): 0.9, ('ttl', 'destination_ip'): 0.91, ('ttl', 'protocol'): 0.87, ('ttl', 'source_port'): 0.9, ('ttl', 'destination_port'): 0.9, ('source_ip', 'destination_ip'): 0.91, ('source_ip', 'protocol'): 0.9, ('source_ip', 'source_port'): 0.91, ('source_ip', 'destination_port'): 0.9, ('destination_ip', 'protocol'): 0.9, ('destination_ip', 'source_port'): 0.91, ('destination_ip', 'destination_port'): 0.91, ('protocol', 'source_port'): 0.87, ('protocol', 'destination_port'): 0.87, ('source_port', 'destination_port'): 0.91}
    
    
    def sort_entropy_diff_pairs(self, entropies_normal, entropies_attack):
        """
        按熵值差异排序字段对。
        
        参数：
        - entropies_normal: dict, 正常流量的字段对熵值
        - entropies_attack: dict, 攻击流量的字段对熵值
        
        返回：
        - sorted_pairs: list, 按熵值差异排序的字段对列表
        """
        diff_pairs = {}
        for pair in entropies_normal.keys():
            diff = abs(np.mean(entropies_normal[pair] - np.mean(entropies_attack[pair])))
            diff_pairs[pair] = diff
        sorted_pairs = sorted(diff_pairs.items(), key=lambda x: x[1], reverse=True)
        return sorted_pairs
    
    def find_key_pair(self, packet_info):
        current_profile = calculate_entropies_for_all_pairs(packet_info)

        # 按熵值差异排序字段对
        sorted_pairs = self.sort_entropy_diff_pairs(self.normal_profile, current_profile)
        print("\nSorted pairs by entropy difference:")
        for pair, diff in sorted_pairs:
            print(f"{pair}: {diff:.4f}")
        
        return sorted_pairs[0][0]

    def detect(self, data_dict: Dict):
        """
        根据熵值检测是否存在DDoS攻击。
        :param data_dict: 来自交换机的数据字典，包括交换机名和数据包信息。
        :return: 检测结果，是否存在DDoS攻击。
        """
        switch = data_dict.get('switch')
        packets_info = data_dict.get('packets_info', [])

        if not packets_info:
            print(f"[{switch}] No packets to analyze.")
            return False
        
        cleaned_packets_info = clean_pkt_info(packets_info)
        if not self.enouth:
            self.key_pair = self.find_key_pair(cleaned_packets_info)
            print(f"Key pair is {self.key_pair}")
            self.enouth = True
            
        else:
            entropy_value = calculate_entropy(cleaned_packets_info, self.key_pair)
            print(entropy_value)
            # detect_result = self.detect_entropy_anomaly(entropy_values)
            if entropy_value > self.threshold:
                print(f"Detect result is Normal")
            else:
                print(f"Detect result is Attack")

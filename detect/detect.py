import math
import numpy as np
from collections import Counter
from typing import List, Dict
from itertools import combinations
from utils.clean import clean_pkt_info

class Detector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.columns = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_length", "ttl"]

    def calculate_entropy(self, column_pair, data: List[str]) -> float:
        """
        根据数据计算熵。
        :param data: 数据列表，例如源IP地址列表。
        :return: 计算得到的熵值。
        """
        
        pair_data = []
        for data_item in data:
            tuple_of_data = tuple(data_item[column] for column in column_pair)
            pair_data.append(tuple_of_data)

        total = len(pair_data)
        if total == 0:
            return 0.0

        counter = Counter(pair_data)
        probabilities = [count / total for count in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        # print(pair_data)
        if len(counter) == 1:
            return 0.0
        return entropy / math.log2(len(counter))
    
    def calculate_entropies_for_all_pairs(self, columns, label=None):
        """
        计算所有字段对的熵值。
        
        参数：
        - file_path: str, CSV 文件路径
        - columns: list, 所有可选的字段名
        - label: int, 数据标签 (0: 正常, 1: 攻击)
        - batch_size: int, 每个流量周期的数据包数量
        
        返回：
        - result: dict, 每个字段对组合的熵值列表
        """
        result = {}
        for column_pair in combinations(columns, 3):  # 遍历所有可能的列对组合
            entropy_values = self.calculate_entropy(column_pair, label)
            result[column_pair] = entropy_values
            avg_entropy = np.mean(entropy_values)
            if label == 0:
                print(f"字段对 {column_pair} 的平均熵值(Normal): {avg_entropy}")
            else:
                print(f"字段对 {column_pair} 的平均熵值(Attack): {avg_entropy}")
        return result
    
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
            diff = np.mean(entropies_normal[pair] - np.mean(entropies_attack[pair]))
            diff_pairs[pair] = diff
        sorted_pairs = sorted(diff_pairs.items(), key=lambda x: x[1], reverse=True)
        return sorted_pairs
    
    def find_key_pair(self, data):
        """
        找到熵值差异最大的字段对。
        
        参数：
        -
        
        返回：
        - key_pair: tuple, 熵值差异最大的字段对
        """
        # 计算正常流量的所有字段对的熵
        print("For Normal Traffic:")
        entropies_normal = self.calculate_entropies_for_all_pairs(self.columns, label=0)

        # 计算攻击流量的所有字段对的熵
        print("For Attack Traffic:")
        entropies_attack = self.calculate_entropies_for_all_pairs(self.columns, label=1)

        # 按熵值差异排序字段对
        sorted_pairs = self.sort_entropy_diff_pairs(entropies_normal, entropies_attack)
        print("\nSorted pairs by entropy difference:")
        for pair, diff in sorted_pairs:
            print(f"{pair}: {diff:.4f}")
        
        return sorted_pairs[0][0]
    
    def detect_entropy_anomaly(self, entropy_values):
        """
        检测熵值异常。
        
        参数：
        - entropy_values: list, 熵值列表
        
        返回：
        - detect_result: dict, 每个周期的检测结果
        """
        detect_result = {}
        for i, entropy_value in enumerate(entropy_values):
            if entropy_value > self.threshold:
                detect_result[i+1] = 'normal'
            else:
                detect_result[i+1] = 'attack'
        
        return detect_result

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

        # key_pair = self.find_key_pair(cleaned_packets_info)
        # print(key_pair)
        key_pair = ['destination_ip']
        entropy_value = self.calculate_entropy(key_pair, cleaned_packets_info)
        print(entropy_value)
        # detect_result = self.detect_entropy_anomaly(entropy_values)
        if entropy_value > self.threshold:
            print(f"Detect result is Normal")
        else:
            print(f"Detect result is Attack")
    
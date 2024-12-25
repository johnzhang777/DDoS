import math
from collections import Counter
from typing import List, Dict

class Detector:
    def __init__(self, threshold):
        self.threshold = threshold

    def calculate_entropy(self, data: List[str]) -> float:
        """
        根据数据计算熵。
        :param data: 数据列表，例如源IP地址列表。
        :return: 计算得到的熵值。
        """
        total = len(data)
        if total == 0:
            return 0.0

        counter = Counter(data)
        probabilities = [count / total for count in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        print(data)
        if len(counter) == 1:
            return 0.0
        return entropy / math.log2(len(counter))

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

        # 提取所有数据包的源IP地址
        source_ips = [packet['source_ip'] for packet in packets_info if packet['source_ip']]
        destination_ips = [packet['destination_ip'] for packet in packets_info if packet['destination_ip']]

        # 计算熵值
        entropy = self.calculate_entropy(destination_ips)

        # 判断是否为DDoS攻击
        if entropy < self.threshold:
            print(f"[{switch}] Possible DDoS attack detected! Entropy: {entropy:.4f}")
            return True
        else:
            print(f"[{switch}] Normal traffic. Entropy: {entropy:.4f}")
            return False
    
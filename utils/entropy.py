import numpy as np
import math
from itertools import combinations
from collections import Counter

def calculate_entropy(packet_info, column_pair):
    pair_data = []
    for data_item in packet_info:
        tuple_of_data = tuple(data_item[column] for column in column_pair)
        pair_data.append(tuple_of_data)

    total = len(pair_data)
    if total == 0:
        return 0.0

    counter = Counter(pair_data)
    probabilities = [count / total for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    if len(counter) == 1:
        return 0.0
    normalized_entropy = entropy / math.log2(len(counter))
    return normalized_entropy

def calculate_entropies_for_all_pairs(packet_info, columns = ['packet_length', 'ttl', 'source_ip', 'destination_ip', 
               'protocol', 'source_port', 'destination_port']):
    result = {}
    for column_pair in combinations(columns, 2):  # 遍历所有可能的列对组合
        entropy_values = calculate_entropy(packet_info, column_pair)
        result[column_pair] = entropy_values
    return result
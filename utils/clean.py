from IPy import IP
def clean_pkt_info(pkt_info: list):
    cleaned_pkt_info = []
    for pkt in pkt_info:
        pkt_new = {}
        # handle ip
        pkt_new['source_ip'] = int(IP(pkt['source_ip']).int())
        pkt_new['destination_ip'] = int(IP(pkt['destination_ip']).int())

        # handle port
        pkt_new['source_port'] = int(next(iter(pkt['source_port'].values()))) if pkt['source_port'] else 0
        pkt_new['destination_port'] = int(next(iter(pkt['destination_port'].values()))) if pkt['destination_port'] else 0

        # handle protocol
        pkt_new['protocol'] = int(pkt['protocol'])

        # handle packet size
        pkt_new['packet_length'] = int(pkt['packet_length'])

        # handle ttl
        pkt_new['ttl'] = int(pkt['ttl'])

        # handle tcp flags
        # print(pkt['tcp_flags'])
        if pkt['tcp_flags']:  # 检查是否有 tcp_flags 属性
            try:
                # 获取 tcp_flags 的实际值
                if not isinstance(pkt['tcp_flags'], str):
                    # 尝试从 LayerFieldsContainer 中提取值
                    tcp_flags_value = str(pkt['tcp_flags'])
                else:
                    tcp_flags_value = pkt['tcp_flags']

                # 转换为整数
                pkt_new['tcp_flags'] = int(tcp_flags_value, 16) if isinstance(tcp_flags_value, str) else int(tcp_flags_value)
            except Exception as e:
                # 如果转换失败，设置默认值为 0
                print("Error: Invalid tcp_flags value:", e)
                pkt_new['tcp_flags'] = 0
        else:
            pkt_new['tcp_flags'] = 0
        cleaned_pkt_info.append(pkt_new)

    return cleaned_pkt_info

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
        if hasattr(pkt, 'tcp_flags'):  # 修正为正确的 hasattr 方法
            try:
                # 尝试将 tcp_flags 转换为整数，假设可能是16进制字符串
                pkt_new['tcp_flags'] = int(pkt['tcp_flags'], 16) if isinstance(pkt['tcp_flags'], str) else int(pkt['tcp_flags'])
            except (ValueError, TypeError):
                # 如果转换失败，设置默认值为0
                pkt_new['tcp_flags'] = 0
        else:
            pkt_new['tcp_flags'] = 0

        # handle flag
        if pkt['flag'].startswith("Normal"):
            pkt_new['flag'] = 0
        else:
            pkt_new['flag'] = 1

        cleaned_pkt_info.append(pkt_new)

    return cleaned_pkt_info

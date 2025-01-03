from IPy import IP

class Clean:

    def handle_ip(data):
        '''
            convert IP addresses to integers
        '''

        # Function to check if string is a MAC address
        def is_mac_address(addr):
            # MAC address format: xx:xx:xx:xx:xx:xx
            return len(addr.split(':')) == 6 and all(len(x) == 2 for x in addr.split(':'))

        # Remove rows with MAC addresses
        data = data[~data['srcip'].apply(is_mac_address)]
        data = data[~data['dstip'].apply(is_mac_address)]

        # Convert remaining valid IP addresses to integers
        data['srcip'] = data['source_ip'].apply(lambda x: int(IP(x).int()))
        data['dstip'] = data['destination_ip'].apply(lambda x: int(IP(x).int()))

        return data

    def clean_pkt_info(self, pkt_info: list):
        pass
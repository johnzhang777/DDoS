from log.log import LoggerConfig
import traceback
import re

logger = LoggerConfig.get_logger(__name__)

def decode_payload(payload_str, default="Normal"):
        try:
            if not payload_str.startswith("Normal"):
                payload_str = bytes.fromhex(payload_str.replace(':', '')).decode('utf-8', errors='ignore')
                if not re.search(r"(Normal|Attack)", payload_str):
                    return "Normal"
                match = re.search(r"(\w+)Attack", payload_str)
                if match:
                    return match.group(0)
            return payload_str
        except Exception as e:
            return default

def parse_packet(packet):
        packet_info = {
            'packet_length': None,
            'ttl': None,
            'source_mac': None,
            'destination_mac': None,
            'source_ip': None,
            'destination_ip': None,
            'protocol': None,
            'source_port': {},
            'destination_port': {},
            'flag': None,
            'tcp_flags': None
        }

        try:
            payload = None
            packet_info['packet_length'] = getattr(packet, 'length', None)

            if 'eth' in packet:
                packet_info['source_mac'] = packet.eth.src
                packet_info['destination_mac'] = packet.eth.dst

            if 'ip' not in packet:
                packet_info['flag'] = "NoIPProtocol"
                return None

            ip_layer = packet.ip
            packet_info.update({
                'source_ip': ip_layer.src,
                'destination_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl
            })

            if 'tcp' in packet:
                tcp_layer = packet.tcp
                packet_info['source_port']['tcp'] = tcp_layer.srcport
                packet_info['destination_port']['tcp'] = tcp_layer.dstport
                packet_info['tcp_flags'] = tcp_layer.flags
                payload = getattr(tcp_layer, 'payload', 'NormalTCPTraffic')
                payload = decode_payload(payload, "Normal")

            if 'udp' in packet:
                udp_layer = packet.udp
                packet_info['source_port']['udp'] = udp_layer.srcport
                packet_info['destination_port']['udp'] = udp_layer.dstport
                udp_data = getattr(udp_layer, 'data', None)
                if not udp_data:
                    payload = "Normal"
                else:
                    payload = getattr(udp_data, 'data', 'NormalUDPTraffic')
                payload = decode_payload(payload, "Normal")

            # if 'icmp' in packet:
            #     icmp_layer = packet.icmp
            #     packet_info['icmp_type'] = icmp_layer.type
            #     packet_info['icmp_code'] = icmp_layer.code
            #     payload = getattr(icmp_layer, 'data', 'NormalICMPTraffic')
            #     payload = self.decode_payload(payload, "Normal")

        except AttributeError as ae:
            logger.error(f"AttributeError while parsing packet: {ae}")
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")
            logger.error(traceback.format_exc(), exc_info=True)

        packet_info['flag'] = payload or "Normal"
        # logger.info(packet_info['flag'])
        return packet_info
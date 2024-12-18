# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import in_proto, ipv4, icmp, tcp, udp
from config.config import Config

import socket
import threading
import json

global FLOW_SERIAL_NO
FLOW_SERIAL_NO = 0


def get_flow_number():
    global FLOW_SERIAL_NO
    FLOW_SERIAL_NO = FLOW_SERIAL_NO + 1
    return FLOW_SERIAL_NO

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.config = Config()
        self.server_ip, self.server_port = self.config.get_server()  
        self.start_socket_server()
        self.datapaths = {}

    def start_socket_server(self):
        """启动 Socket 服务器线程"""
        server_thread = threading.Thread(target=self.socket_server)
        server_thread.daemon = True  # 后台运行
        server_thread.start()
        self.logger.info("Socket server started on port %d", self.server_port)

    def socket_server(self):
        """Socket 服务器，支持多客户端连接和大数据接收"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.server_ip, self.server_port))
        server_socket.listen(5)
        self.logger.info("Socket server listening at %s:%d", self.server_ip, self.server_port)

        while True:
            conn, addr = server_socket.accept()
            self.logger.info("Connection established with %s", addr)

            # 为每个客户端启动一个独立的线程处理
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

    def handle_client(self, conn: socket.socket, addr):
        """处理客户端连接，支持持续数据接收"""
        try:
            while True:
                # 读取 4 字节的头部，获取数据长度
                data_length_bytes = self.recv_all(conn, 4)
                if not data_length_bytes:
                    break  # 客户端断开

                data_length = int.from_bytes(data_length_bytes, byteorder='big')

                # 根据数据长度接收完整数据
                received_data = self.recv_all(conn, data_length)
                if not received_data:
                    break  # 客户端断开

                data_str = received_data.decode()
                data_dict = json.loads(data_str)
                
                # TODO 封装一个detect类来进行检测
                self.calculate_entropy(data_dict)
                # self.logger.info("Received data from %s: %s", addr, data_str)

                # 发送回复
                response = f"Data received from {data_dict['switch']} successfully."
                conn.sendall(response.encode())

        except Exception as e:
            self.logger.error("Error with client %s: %s", addr, e)
        finally:
            conn.close()
            self.logger.info("Connection closed with %s", addr)

    def recv_all(self, conn:socket.socket, length):
        """确保接收指定长度的数据"""
        data = b""
        while len(data) < length:
            chunk = conn.recv(min(1024, length - len(data)))  # 按 1024 字节接收
            if not chunk:
                return None  # 客户端断开
            data += chunk
        return data

    def calculate_entropy(self, data: dict):
        try:
            switch = data['switch']
            packets_info = data['packets_info']
            # TODO 计算熵
            print(switch, packets_info[99])
            # print(type(self.datapaths[1]))
        except Exception as e:
            self.logger.error("Error calculating entropy: %s", e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        flow_serial_no = get_flow_number()
        self.add_flow(datapath, 0, match, actions, flow_serial_no)
        self.datapaths[datapath.id] = datapath


    def add_flow(self, datapath, priority, match, actions, serial_no, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, buffer_id=buffer_id,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, priority=priority,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global match
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        length = msg.total_len

        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        mac_dst = eth.dst
        mac_src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][mac_src] = in_port

        if mac_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][mac_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                ip_src = ip.src
                ip_dst = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    t = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            eth_src=mac_src, eth_dst=mac_dst,
                                            ipv4_src=ip_src, ipv4_dst=ip_dst,
                                            ip_proto=protocol, icmpv4_code=t.code,
                                            icmpv4_type=t.type)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            eth_src=mac_src, eth_dst=mac_dst,
                                            ip_proto=protocol)

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            eth_src=mac_src, eth_dst=mac_dst,
                                            ipv4_src=ip_src, ipv4_dst=ip_dst,
                                            ip_proto=protocol,
                                            udp_src=u.src_port, udp_dst=u.dst_port)

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    flow_serial_no = get_flow_number()
                    self.add_flow(datapath, 1, match, actions, flow_serial_no, msg.buffer_id, idletime=20, hardtime=100)
                    return
                else:
                    flow_serial_no = get_flow_number()

                    self.add_flow(datapath, 1, match, actions, flow_serial_no, idletime=20, hardtime=100)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
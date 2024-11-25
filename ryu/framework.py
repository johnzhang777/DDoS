from operator import attrgetter
# from ryu.app import simple_switch_13
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib import hub
from switch import SimpleSwitch13

class MyMonitor(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(MyMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor_send_datapath)
        # logging.basicConfig(level=logging.WARNING)
        # logger = logging.getLogger()
        # logger.setLevel(logging.WARNING)
 
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """方法用于对交换机的状态进行监听，比如上线或者下线
        例如：
        ryu.controller.handler.HANDSHAKE_DISPATCHER     交换 HELLO 讯息
        ryu.controller.handler.CONFIG_DISPATCHER       接收SwitchFeatures讯息
        ryu.controller.handler.MAIN_DISPATCHER    一般状态
        ryu.controller.handler.DEAD_DISPATCHER    联机中断"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
 
    def _monitor_send_datapath(self):
        """周期性的换机发送请求数据
        通过调用_request_status方法"""
        while True:
            for dp in self.datapaths.values():
                self._request_status(dp)
            hub.sleep(10)
 
    def _request_status(self, datapath):
        """方法用于控制器向交换机发送状态请求信息，
        比如说端口状态信息请求、流表状态信息请求等
        datapath是传递的交换机参数，用于明确向哪一个交换机发送请求信息"""
 
        """对于方法的实现
        在ofproto_v1_3_parser中有例子进行解释
        Example::
        def send_port_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
            datapath.send_msg(req)"""
 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
 
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_status_reply_handler(self, ev):
        """方法用来解析交换机返回的流表的数据，并将其在终端中打印出来"""
        body = ev.msg.body

        self.logger.info("Flow Stats Reply from datapath: %016x", ev.msg.datapath.id)

        self.logger.info("%16s %16s %10s %18s %18s %5s %5s %3s %3s %3s %3s %3s" % (
                "IP Src", "IP Dst", "IP Proto", "Eth Src", "Eth Dst", "Port Src", "Port Dst", "Action Port", "Action Type", "package count", "byte count", "duration"))

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'], flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            # eth_type = stat.match['eth_type']
            eth_src = stat.match['eth_src']
            eth_dst = stat.match['eth_dst']
            port_src = stat.match.get('tcp_src', stat.match.get('udp_src', 'N/A'))
            port_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 'N/A'))
            action_port = stat.instructions[0].actions[0].port
            type = stat.instructions[0].actions[0].type
            # length = stat.match['length']
            # 获取流的统计信息
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            # 计算流的持续时间
            duration_sec = stat.duration_sec
            duration_nsec = stat.duration_nsec
            duration = round(duration_sec + duration_nsec * 10 ** -9, 4)

            self.logger.info("%16s %16s %10s %18s %18s %5s %5s %3s %3s %3s %3s %3s" % (
                ip_src, ip_dst, ip_proto, eth_src, eth_dst, port_src, port_dst, action_port, type, packet_count, byte_count, duration))
 
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_status_reply_handler(self, ev):
        """方法用来解析交换机返回的流表的数据，并将其在终端中打印出来"""
        body = ev.msg.body
        self.logger.info("Port Stats Reply from datapath: %016x", ev.msg.datapath.id)

        self.logger.info('%-8s %-8s %-8s %-8s %-8s %-8s',
                        'datapath', 'port_no', 'rx-pkts', 'tx-pkts', 'rx-bytes', 'tx-bytes')

        for stat in body:
            self.logger.info('%08x %-8x %-8d %-8d %-8d %-8d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.tx_packets,
                            stat.rx_bytes, stat.tx_bytes)
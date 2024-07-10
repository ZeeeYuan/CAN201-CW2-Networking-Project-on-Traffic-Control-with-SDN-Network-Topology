from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp

client_ip = '10.0.1.5'
client_mac = '00:00:00:00:00:03'

server_1_ip = '10.0.1.2'
server_1_mac = '00:00:00:00:00:01'

server_2_ip = '10.0.1.3'
server_2_mac = '00:00:00:00:00:02'


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    def add_flow_pkt_in(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority,
                                    match=match, instructions=inst, idle_timeout=5)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, idle_timeout=5)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("Packet_In SDN packet: switch = %s, src = %s, dst = %s, in_port = %s",
                         dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            # ARP Traffic
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst,
                                        eth_src=src)

            # IP Datagram
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                ip_src = ipv4_pkt.src
                ip_dst = ipv4_pkt.dst
                ip_protocol = ipv4_pkt.proto

                # ICMP
                if ip_protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=ip_src,
                                            ipv4_dst=ip_dst, ip_proto=ip_protocol)

                # UDP
                elif ip_protocol == in_proto.IPPROTO_UDP:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=ip_src,
                                            ipv4_dst=ip_dst, ip_proto=ip_protocol, udp_src=udp_pkt.src_port,
                                            udp_dst=udp_pkt.dst_port)

                # TCP
                elif ip_protocol == in_proto.IPPROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    is_syn = tcp_pkt.bits & tcp.TCP_SYN != 0 and tcp_pkt.bits & tcp.TCP_ACK == 0
                    if is_syn:
                        self.logger.info("TCP SYN segment received.")
                    # Modify destination to redirect traffic to server 2
                    if ip_src == client_ip and ip_dst == server_1_ip:
                        if server_2_mac in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][server_2_mac]
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)

                        actions = [parser.OFPActionSetField(eth_dst=server_2_mac),
                                   parser.OFPActionSetField(ipv4_dst=server_2_ip),
                                   parser.OFPActionOutput(port=out_port)]
                    # Modify source to disguise as server 1 caz client is unaware of server 2
                    elif ip_src == server_2_ip and ip_dst == client_ip:
                        if client_mac in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][client_mac]
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)

                        actions = [parser.OFPActionSetField(eth_src=server_1_mac),
                                   parser.OFPActionSetField(ipv4_src=server_1_ip),
                                   parser.OFPActionOutput(port=out_port)]

                    else:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port,
                                                ipv4_dst=ip_dst, ip_proto=ip_protocol, tcp_dst=tcp_pkt.dst_port)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow_pkt_in(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow_pkt_in(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        self.logger.info("Packet_Out SDN packet: switch = %s, in_port = %s, actions = %s, buffer_id = %s",
                         dpid, in_port, actions, msg.buffer_id)

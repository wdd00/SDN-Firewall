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
import json
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
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


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
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # read from rules json file and add corresponding rules.
        priority = 10
        with open('rules.json') as f:
            rules = json.load(f)
            for rule in rules['rules']:
                if 'protocol' not in rule:
                    #print(ipv4_src, " ", ipv4_dst)
                    if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                        if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=rule['ipv4_src'],
                                                    ipv4_dst=rule['ipv4_dst'])
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=rule['ipv4_src'])
                    elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_dst=rule['ipv4_dst'])
                    else:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)

                if 'protocol' in rule and rule['protocol'] == "icmp":
                    #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_ICMP)
                    if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                        if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=rule['ipv4_src'],
                                                    ipv4_dst=rule['ipv4_dst'],
                                                    ip_proto=in_proto.IPPROTO_ICMP)
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=rule['ipv4_src'],
                                                    ip_proto=in_proto.IPPROTO_ICMP)
                    elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ipv4_dst=rule['ipv4_dst'],
                                                ip_proto=in_proto.IPPROTO_ICMP)
                    else:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                ip_proto=in_proto.IPPROTO_ICMP)

                if 'protocol' in rule and rule['protocol'] == "tcp":
                    if 'src_port' in rule and rule['src_port'] != "any":
                        if 'dst_port' in rule and rule['src_port'] != "any":
                            #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_TCP, " ", rule['src_port'], " ", rule['dst_port'])
                            if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                                if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ipv4_dst=rule['ipv4_dst'],
                                                            ip_proto=in_proto.IPPROTO_TCP,
                                                            tcp_src=rule['src_port'],
                                                            tcp_dst=rule['dst_port'])
                                else:
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ip_proto=in_proto.IPPROTO_TCP,
                                                            tcp_src=rule['src_port'],
                                                            tcp_dst=rule['dst_port'])
                            elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_src=rule['src_port'],
                                                        tcp_dst=rule['dst_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_src=rule['src_port'],
                                                        tcp_dst=rule['dst_port'])
                        else:
                            #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_TCP, " ", rule['src_port'])
                            if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                                if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ipv4_dst=rule['ipv4_dst'],
                                                            ip_proto=in_proto.IPPROTO_TCP,
                                                            tcp_src=rule['src_port'])
                                else:
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ip_proto=in_proto.IPPROTO_TCP,
                                                            tcp_src=rule['src_port'])
                            elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_src=rule['src_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_src=rule['src_port'])
                    elif 'dst_port' in rule and rule['dst_port'] != "any":
                        #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_TCP, " ",rule['dst_port'])
                        if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                            if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_dst=rule['dst_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ip_proto=in_proto.IPPROTO_TCP,
                                                        tcp_dst=rule['dst_port'])
                        elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=rule['ipv4_dst'],
                                                    ip_proto=in_proto.IPPROTO_TCP,
                                                    tcp_dst=rule['dst_port'])
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ip_proto=in_proto.IPPROTO_TCP,
                                                    tcp_dst=rule['dst_port'])
                    else:
                        #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_TCP)
                        if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                            if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_TCP)
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ip_proto=in_proto.IPPROTO_TCP)
                        elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=rule['ipv4_dst'],
                                                    ip_proto=in_proto.IPPROTO_TCP)
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ip_proto=in_proto.IPPROTO_TCP)

                if 'protocol' in rule and rule['protocol'] == "udp":
                    if 'src_port' in rule and rule['src_port'] != "any":
                        if 'dst_port' in rule and rule['src_port'] != "any":
                            #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_UDP, " ", rule['src_port'], " ", rule['dst_port'])
                            if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                                if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ipv4_dst=rule['ipv4_dst'],
                                                            ip_proto=in_proto.IPPROTO_UDP,
                                                            tcp_src=rule['src_port'],
                                                            tcp_dst=rule['dst_port'])
                                else:
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ip_proto=in_proto.IPPROTO_UDP,
                                                            tcp_src=rule['src_port'],
                                                            tcp_dst=rule['dst_port'])
                            elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_src=rule['src_port'],
                                                        tcp_dst=rule['dst_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_src=rule['src_port'],
                                                        tcp_dst=rule['dst_port'])
                        else:
                            #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_UDP, " ", rule['src_port'])
                            if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                                if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ipv4_dst=rule['ipv4_dst'],
                                                            ip_proto=in_proto.IPPROTO_UDP,
                                                            tcp_src=rule['src_port'])
                                else:
                                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                            ipv4_src=rule['ipv4_src'],
                                                            ip_proto=in_proto.IPPROTO_UDP,
                                                            tcp_src=rule['src_port'])
                            elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_src=rule['src_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_src=rule['src_port'])
                    elif 'dst_port' in rule and rule['dst_port'] != "any":
                        #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_UDP, " ", rule['dst_port'])
                        if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                            if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_dst=rule['dst_port'])
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ip_proto=in_proto.IPPROTO_UDP,
                                                        tcp_dst=rule['dst_port'])
                        elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=rule['ipv4_dst'],
                                                    ip_proto=in_proto.IPPROTO_UDP,
                                                    tcp_dst=rule['dst_port'])
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ip_proto=in_proto.IPPROTO_UDP,
                                                    tcp_dst=rule['dst_port'])
                    else:
                        #print(ipv4_src, " ", ipv4_dst, " ", in_proto.IPPROTO_UDP)
                        if 'ipv4_src' in rule and rule['ipv4_src'] != "any":
                            if 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ipv4_dst=rule['ipv4_dst'],
                                                        ip_proto=in_proto.IPPROTO_UDP)
                            else:
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                        ipv4_src=rule['ipv4_src'],
                                                        ip_proto=in_proto.IPPROTO_UDP)
                        elif 'ipv4_dst' in rule and rule['ipv4_dst'] != "any":
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_dst=rule['ipv4_dst'],
                                                    ip_proto=in_proto.IPPROTO_UDP)
                        else:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ip_proto=in_proto.IPPROTO_UDP)
                actions = [] # Drop
                self.add_flow(datapath, priority, match, actions)
                priority -= 1

#        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
#                                ipv4_src="10.1.1.1",
#                                ipv4_dst="10.1.1.2")
#        actions = [] #Drop
#        self.add_flow(datapath, 3, match, actions)

#        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
#                                ipv4_dst="10.1.1.4",
#                                ip_proto=in_proto.IPPROTO_ICMP)
#        actions = [] #Drop
#        self.add_flow(datapath, 2, match, actions)

#        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
#                                ipv4_src="10.1.1.3",
#                                ipv4_dst="10.1.1.4",
#                                ip_proto=in_proto.IPPROTO_TCP,
#                                tcp_dst=80)
#        actions = [] #Drop
#        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

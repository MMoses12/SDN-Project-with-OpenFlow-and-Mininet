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

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""

"""
    Gavouras Dimitrios 03145
    Kafantaris Konstantinos 03230
    Moysis Moysis 03250
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

MAC_TO_IP = {
    '192.168.1.1': '00:00:00:00:01:01',
    '192.168.1.2': '00:00:00:00:01:02',
    '192.168.1.3': '00:00:00:00:01:03',
    '192.168.2.1': '00:00:00:00:02:01',
    '192.168.2.2': '00:00:00:00:02:02',
    '192.168.2.3': '00:00:00:00:02:03'
}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                self.handle_arp(pkt, datapath, msg.in_port, eth)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                self.handle_ip(pkt, datapath, msg.in_port, eth)
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                self.handle_arp(pkt, datapath, msg.in_port, eth)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                self.handle_ip_right(pkt, datapath, msg.in_port, eth)
                return
            return
                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    """
    fill in the code here for the ARP reply functions.
    """
    # Handle ARP packets.
    def handle_arp(self, pkt, datapath, in_port, eth):
        arp_pkt = pkt.get_protocol(arp.arp)
        print("ARP packet from: " + str(arp_pkt.src_ip) + " to: " + str(arp_pkt.dst_ip))

        # If packet goes to left switch.
        if arp_pkt.dst_ip == "192.168.1.1":
            src_mac = "00:00:00:00:01:01"
            src_ip = "192.168.1.1"
            dst_ip = arp_pkt.src_ip
            dst_mac = eth.src

            # self.logger.info("Left LAN packet " + dst_ip)
        
        # If packet goes to right switch.
        elif arp_pkt.dst_ip == "192.168.2.1":
            src_mac = "00:00:00:00:02:01"
            src_ip = "192.168.2.1"
            dst_ip = arp_pkt.src_ip
            dst_mac = eth.src

            # self.logger.info("Right LAN packet")

        #  If packet goes from a switch to a host.
        else:
            src_mac = eth.src
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            dst_mac = eth.dst
        
        # Make arp_reply packet.
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype = eth.ethertype,
            dst = dst_mac,
            src = src_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode = arp.ARP_REPLY,
            src_mac = src_mac,
            src_ip = src_ip,
            dst_mac = dst_mac,
            dst_ip = dst_ip
        ))
        arp_reply.serialize()

        # Send arp reply packet.
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER, 
            actions=actions, 
            data=arp_reply.data)
        datapath.send_msg(out)

    # Handle IP packets.
    def handle_ip(self, pkt, datapath, in_port, eth):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        print("ARP packet from: " + str(ip_pkt.src) + " to: " + str(ip_pkt.dst))

        # Get the destination MAC from the table. 
        dst_mac = MAC_TO_IP.get(ip_pkt.dst)

        # Determine output port based on the destination IP
        if ip_pkt.dst.startswith('192.168.1'):
            # print("Left LAN " + dst_mac)
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:01:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:01:01"
            out_port = 2  # Assuming port 1 connects to 192.168.1.0/24 network
        elif ip_pkt.dst.startswith('192.168.2'):
            # print("Right LAN " + dst_mac)
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:02:01", ethertype=eth.ethertype)
            out_port = 1  # Assuming port 2 connects to 192.168.2.0/24 network
            src_mac = "00:00:00:00:02:01"
        else:
            self.logger.info("Invalid")
            return
        
        ipv4_pkt = ipv4.ipv4(dst=ip_pkt.dst, src=ip_pkt.src, proto=ip_pkt.proto)

        # Add protocols to packet header.
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)
        pkt.serialize()

        # Send packet.
        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(src_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(dst_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        match = datapath.ofproto_parser.OFPMatch(
            dl_type=ether_types.ETH_TYPE_IP,
            nw_src=ip_pkt.src,
            nw_dst=ip_pkt.dst
        )
        
        self.add_flow(datapath, match, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=pkt.data)
        datapath.send_msg(out)

        # Handle IP packets.
    def handle_ip_right(self, pkt, datapath, in_port, eth):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        print("ARP packet from: " + str(ip_pkt.src) + " to: " + str(ip_pkt.dst))

        # Get the destination MAC from the table. 
        dst_mac = MAC_TO_IP.get(ip_pkt.dst)

        # Determine output port based on the destination IP
        if ip_pkt.dst.startswith('192.168.1'):
            # print("Left LAN " + dst_mac)
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:01:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:01:01"
            out_port = 1  # Assuming port 1 connects to 192.168.1.0/24 network
        elif ip_pkt.dst.startswith('192.168.2'):
            # print("Right LAN " + dst_mac)
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:02:01", ethertype=eth.ethertype)
            out_port = 2  # Assuming port 2 connects to 192.168.2.0/24 network
            src_mac = "00:00:00:00:02:01"
        else:
            self.logger.info("Invalid")
            return
        
        ipv4_pkt = ipv4.ipv4(dst=ip_pkt.dst, src=ip_pkt.src, proto=ip_pkt.proto)

        # Add protocols to packet header.
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)
        pkt.serialize()

        # Send packet.
        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(src_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(dst_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        match = datapath.ofproto_parser.OFPMatch(
            dl_type=ether_types.ETH_TYPE_IP,
            nw_src=ip_pkt.src,
            nw_dst=ip_pkt.dst
        )
        
        self.add_flow(datapath, match, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=pkt.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

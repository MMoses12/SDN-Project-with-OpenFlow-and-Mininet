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
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import vlan
from ryu.lib.packet import icmp
from ryu.ofproto import inet

# Main Trunk Port configuration
MAIN_TRUNK_PORT = (1,)

network_switch_ports = {
# Main Trunk Port configuration
# MAC to IP address mapping for VLAN 200
	2: {
		'trunk_ports': MAIN_TRUNK_PORT,
		'vlan_100_mappings': (2, 3),
# Main Trunk Port configuration
# MAC to IP address mapping for VLAN 200
		'vlan_200_mappings': (4,)
	},
	3: {
		'trunk_ports': MAIN_TRUNK_PORT,
		'vlan_100_mappings': (4,),
		'vlan_200_mappings': (2, 3)
	}
}

mac_to_ip_mapping = {
    # MAC to IP address mapping for VLAN 100
    '192.168.1.1': '00:00:00:00:01:01',
    '192.168.1.2': '00:00:00:00:01:02',  #h1
    '192.168.1.3': '00:00:00:00:01:03',  #h4
    # MAC to IP address mapping for VLAN 200
    '192.168.2.1': '00:00:00:00:02:01',
    '192.168.2.2': '00:00:00:00:02:02',  #h2
    '192.168.2.3': '00:00:00:00:02:03'   #h3
}

# VLAN 100 known IPs and MACs.
vlan_100_mappings = {
    '192.168.1.1': '00:00:00:00:01:01' ,
    '192.168.1.2': '00:00:00:00:01:02',
    '192.168.1.3': '00:00:00:00:01:03'
}

# VLAN 200 known IPs and MACs.
vlan_200_mappings = {
    '192.168.2.1': '00:00:00:00:02:01',
    '192.168.2.3': '00:00:00:00:02:03',
    '192.168.2.2': '00:00:00:00:02:02'
}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        super(SimpleSwitch, self).__init__(*args, **kwargs) 	
        
        # Used for known ports.
        self.mac_to_port = {}

        # Used for VLAN 100 
        self.mac_to_port_vlan_100 = {}

        # Used for VLAN 200
        self.mac_to_port_vlan_200 = {}
        
    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    # -- HANDLE PACKET WITH PRIORITY --
    # Add new flows in order to handle future packets with priority (-S 8 ToS)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        match, actions = None, []

        if dpid in [0x1A, 0x1B]:
            if dpid == 0x1A:
                match = self.create_ip_match(datapath, '192.168.2.0', 24, 8)
                actions = self.create_flow_actions(datapath, "00:00:00:00:05:01", "00:00:00:00:05:02", 4)
            elif dpid == 0x1B:
                match = self.create_ip_match(datapath, '192.168.1.0', 24, 8)
                actions = self.create_flow_actions(datapath, "00:00:00:00:05:02", "00:00:00:00:05:01", 4)

            self.add_flow(datapath, match, actions)

    def create_ip_match(self, datapath, nw_dst, nw_dst_mask, nw_tos):
        return datapath.ofproto_parser.OFPMatch(
            dl_type=ether_types.ETH_TYPE_IP, nw_dst=nw_dst, nw_dst_mask=nw_dst_mask, nw_tos=nw_tos)

    def create_flow_actions(self, datapath, src_mac, dst_mac, out_port):
        return [
            datapath.ofproto_parser.OFPActionSetDlSrc(src_mac),
            datapath.ofproto_parser.OFPActionSetDlDst(dst_mac),
            datapath.ofproto_parser.OFPActionOutput(out_port)
        ]
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        actions = []

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        # Initialize MAC to port tables as empty
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port_vlan_100.setdefault(dpid, {})
        self.mac_to_port_vlan_200.setdefault(dpid, {})

        self.logger.info("\npacket in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            print("Router left")
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                print("HANDLE ARP FROM 0X1A")
                arp_pkt = pkt.get_protocol(arp.arp)

                if arp_pkt.opcode == arp.ARP_REQUEST:
                    # ARP Packet must be destined for router
                    if arp_pkt.dst_ip != '192.168.1.1':
                        return
                    
                    actions.append(datapath.ofproto_parser.OFPActionOutput(msg.in_port))
                    self.handle_arp(pkt, datapath, msg.in_port, eth)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                print("HANDLE IP FROM 0X1A")
                self.handle_ip_left(pkt, datapath, msg.in_port, eth, msg)
                return
            return
        
        if dpid == 0x1B:
            print("Router right")
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                print("HANDLE ARP FROM 0X1B")

                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    if arp_pkt.dst_ip != '192.168.2.1':
                        return
                    actions.append(datapath.ofproto_parser.OFPActionOutput(msg.in_port))
                    self.handle_arp(pkt, datapath, msg.in_port, eth)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                print("HANDLE IP FROM 0X1B")
                self.handle_ip_right(pkt, datapath, msg.in_port, eth, msg)
                return
            return
        
        #  Handle vlan packets in switches.
        self.handle_vlan(pkt, msg, dpid, eth, datapath)
    
    # Handle the packets from switches.
    def handle_vlan(self, pkt, msg, dpid, eth, datapath):
        out_ports = []
        vlan_id = None

        # Indicates we don't know packet destination port so it floods.
        flood_pkt = False
        # Indicates that packet came from trunk link.
        trunk_link_pkt = False

        vlan_100_ports = network_switch_ports[dpid]['vlan_100_mappings']
        vlan_200_ports = network_switch_ports[dpid]['vlan_200_mappings']
        handle_trunk_ports = network_switch_ports[dpid]['trunk_ports']

        # Learn MAC address for VLAN 100 if it doesn't exist
        if msg.in_port in vlan_100_ports and eth.src not in self.mac_to_port_vlan_100[dpid]:
            self.mac_to_port_vlan_100[dpid][eth.src] = msg.in_port

        # Learn MAC address for VLAN 200 if it doesn't exist
        elif msg.in_port in vlan_200_ports and eth.src not in self.mac_to_port_vlan_200[dpid]:
            self.mac_to_port_vlan_200[dpid][eth.src] = msg.in_port

        # Handle VLAN-tagged packets
        else:
            if eth.ethertype == ether_types.ETH_TYPE_8021Q:
                vlan_pkt = pkt.get_protocol(vlan.vlan)

                # Learn MAC address for VLAN 100 if VLAN ID is 100
                if vlan_pkt.vid == 100:
                    self.mac_to_port_vlan_100[dpid][eth.src] = msg.in_port
                # Learn MAC address for VLAN 200 if VLAN ID is 200
                else:
                    self.mac_to_port_vlan_200[dpid][eth.src] = msg.in_port

        # Handle packets from VLAN 100 access ports
        if msg.in_port in vlan_100_ports:
            vlan_id = 100
            
            if eth.dst in self.mac_to_port_vlan_100[dpid]:
                out_ports = [self.mac_to_port_vlan_100[dpid][eth.dst]]
            else:
                for access_port in vlan_100_ports:
                    if access_port != msg.in_port:
                        out_ports.append(access_port)
                
                for trunk_port in handle_trunk_ports:
                    out_ports.append(trunk_port)
                
                flood_pkt = True

        # Handle packets from VLAN 200 access ports
        elif msg.in_port in vlan_200_ports:
            vlan_id = 200
            if eth.dst in self.mac_to_port_vlan_200[dpid]:
                out_ports = [self.mac_to_port_vlan_200[dpid][eth.dst]] 
            else:
                for access_port in vlan_200_ports:
                    if access_port != msg.in_port:
                        out_ports.append(access_port)
                
                for trunk_port in handle_trunk_ports:
                    out_ports.append(trunk_port)

                flood_pkt = True

        # Handle packets from trunk ports
        else:
            if eth.ethertype == ether_types.ETH_TYPE_8021Q:
                # Packet came from trunk link so it goes to access link.
                # So the VLAN header must be removed.
                trunk_link_pkt = True
                
                vlan_pkt = pkt.get_protocol(vlan.vlan)
                vlan_id = vlan_pkt.vid
            
                if vlan_pkt.vid == 100:
                    if eth.dst in self.mac_to_port_vlan_100[dpid]:
                        out_ports = [self.mac_to_port_vlan_100[dpid][eth.dst]]
                    else: 
                        out_ports.extend(vlan_100_ports)
                        if msg.in_port not in MAIN_TRUNK_PORT:
                            out_ports.extend([1])
                        flood_pkt = True
                
                elif vlan_pkt.vid == 200:
                    if eth.dst in self.mac_to_port_vlan_200[dpid]:
                        out_ports = [self.mac_to_port_vlan_200[dpid][eth.dst]] 
                    else:
                        out_ports.extend(vlan_200_ports)
                        if msg.in_port not in MAIN_TRUNK_PORT:
                            out_ports.extend([1])
                        flood_pkt = True
                            
            # Handle non-VLAN tagged packets
            else: 
                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=eth.dst)
                self.add_flow(datapath, match, [])
                return

        # Data to send
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = []
        for out_port in out_ports:
            # Remove VLAN header.
            if trunk_link_pkt:
                actions.append(datapath.ofproto_parser.OFPActionStripVlan())
            
            # Add VLAN ID if it goes to trunk link.
            if out_port in MAIN_TRUNK_PORT:
                actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlan_id))
            
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))

        # Send packet out
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

        # Add flow entry to avoid flooding next time
        if flood_pkt:
            return

        if trunk_link_pkt:
            match = datapath.ofproto_parser.OFPMatch(dl_vlan=vlan_pkt.vid, in_port=msg.in_port, dl_dst=eth.dst)
        else:
            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=eth.dst)

        self.add_flow(datapath, match, actions)


    # Handle arp packets and send them.
    def handle_arp(self, pkt, datapath, in_port, eth):
        arp_pkt = pkt.get_protocol(arp.arp)

        # If packet goes to left switch.
        if arp_pkt.dst_ip == "192.168.1.1":
            src_mac = "00:00:00:00:01:01"
            src_ip = "192.168.1.1"
            dst_ip = arp_pkt.src_ip
            dst_mac = eth.src
        
        # If packet goes to right switch.
        elif arp_pkt.dst_ip == "192.168.2.1":
            src_mac = "00:00:00:00:02:01"
            src_ip = "192.168.2.1"
            dst_ip = arp_pkt.src_ip
            dst_mac = eth.src

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
        
    # Handle IP packets from left router.
    def handle_ip_left(self, pkt, datapath, in_port, eth, msg):
        data = msg.data[14:]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        print("IP packet from: " + str(ip_pkt.src) + " to: " + str(ip_pkt.dst))
        dst_mac = eth.dst            

        # If packet goes to left router and comes from VLAN 100.
        if ip_pkt.dst.startswith('192.168.1') and ip_pkt.dst in vlan_100_mappings:
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:01:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:01:01"
            out_port = 2

        #  If packet goes to right router.
        elif ip_pkt.dst.startswith('192.168.2'):
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:02:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:02:01"
            out_port = 1

        # We don't know the packet destination.
        else:
            # Packet came from the other router.
            if in_port == 1:
                src_mac = '00:00:00:00:01:01'
                dst_mac = '00:00:00:00:02:01'
                src_ip = '192.168.1.1'
                out_port = in_port
            # Priority packets.
            elif in_port == 4:
                src_mac = '00:00:00:00:05:01'
                dst_mac = '00:00:00:00:05:02'
                src_ip = '192.168.1.1'
                out_port = in_port 
            # Packet came from switches.
            else:
                print(eth.src)
                src_mac = '00:00:00:00:01:01'
                dst_mac = eth.src
                src_ip = '192.168.1.1'
                out_port = 2

            #  Send ICMP reply.
            icmp_reply = packet.Packet()
            icmp_reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype, dst=dst_mac, src=src_mac))
            icmp_reply.add_protocol(ipv4.ipv4(dst=ip_pkt.src, src=src_ip, proto=inet.IPPROTO_ICMP))
            icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE,
                                                data=icmp.dest_unreach(data_len=len(data), data=data)))
            icmp_reply.serialize()

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions, data=icmp_reply.data)
            datapath.send_msg(out)

            return
        
        # Send ip reply.
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

    # Handle IP packet for the right routers.
    def handle_ip_right(self, pkt, datapath, in_port, eth, msg):
        data = msg.data[14:]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        print("IP packet from: " + str(ip_pkt.src) + " to: " + str(ip_pkt.dst))

        # Get the destination MAC from the table. 
        dst_mac = mac_to_ip_mapping.get(ip_pkt.dst)

        # If packet goes to left switch (so left router).
        if ip_pkt.dst.startswith('192.168.1'):
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:01:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:01:01"
            out_port = 1
        # If the packet comes for VLAN 200 and comes from VLAN 200.
        elif ip_pkt.dst.startswith('192.168.2') and ip_pkt.dst in vlan_200_mappings:
            eth_pkt = ethernet.ethernet(dst=dst_mac, src="00:00:00:00:02:01", ethertype=eth.ethertype)
            src_mac = "00:00:00:00:02:01"
            out_port = 2 
        else:
            # If packet comes from the other router.
            if in_port == 1:
                src_mac = '00:00:00:00:02:01'
                dst_mac = '00:00:00:00:01:01'
                src_ip = '192.168.2.1'
                out_port = in_port
            # Priority packets.
            elif in_port == 4:
                src_mac = '00:00:00:00:05:02'
                dst_mac = '00:00:00:00:05:01'
                src_ip = '192.168.2.1'
                out_port = in_port
            # Packet comes from switches.
            else:
                src_mac = '00:00:00:00:02:01'
                dst_mac = eth.src
                src_ip = '192.168.2.1'
                out_port = 2

            # Send ICMP reply.
            icmp_reply = packet.Packet()
            icmp_reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype, dst=dst_mac, src=src_mac))
            icmp_reply.add_protocol(ipv4.ipv4(dst=ip_pkt.src, src=src_ip, proto=inet.IPPROTO_ICMP))
            icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE,
                                                data=icmp.dest_unreach(data_len=len(data), data=data)))
            icmp_reply.serialize()

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # Send Packet to Router
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions, data=icmp_reply.data)
            datapath.send_msg(out)

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
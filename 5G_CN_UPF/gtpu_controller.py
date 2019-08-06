from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
import json
from webob import Response
import re

'''
SDN Controller that acts as S-P Gateway encapsulating and decapsulating GTP-U traffic
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

simple_switch_instance_name = 'simple_switch_api_app'
url = '/gtpcontroller/'

class GtpuContextInformation:

    def __init__(self, json):
        # Information from authentication function
        self.enb_tun_ip = json['enb_tun_ip']
        self.gw_tun_ip = json['gw_tun_ip']
        self.ue_assigned_ip = json['ue_ip']
        self.gtp_teid = json['teid']

        # TODO: learn eNB mac address
        self.enb_tun_hw_addr = 'c6:69:80:c0:25:ce'
        
        net_ifaces = self.get_net_ifaces_name()
        # Virtual machine with, at least, two interfaces. First one for GTPU endpoint and second to take out decap traffic
        for iface in net_ifaces:
            if iface == "ens3":
                self.gw_tun_hw_addr = self.get_mac_addr(iface)
            elif iface == "ens4":
                self.external_hw_src_addr = self.get_mac_addr(iface)

        # TODO: Learn destination/next-hop mac address
        self.external_hw_dst_addr = "fa:16:3e:bf:a4:ac"

    def to_json(self):
        data = {}
        data['enb_tun_ip'] = str(self.enb_tun_ip)
        data['gw_tun_ip'] = str(self.gw_tun_ip)
        data['enb_tun_hw_addr'] = str(self.enb_tun_hw_addr)
        data['gw_tun_hw_addr'] = str(self.gw_tun_hw_addr)
        data['external_src_mac'] = str(self.external_hw_src_addr)
        data['external_dst_mac'] = str(self.external_hw_dst_addr)
        data['ue_ip'] = str(self.ue_assigned_ip)
        data['teid'] = str(self.gtp_teid)
        return json.dumps(data)

    def get_net_ifaces_name(self):
        net_ifaces = []
        with open('/proc/net/dev') as f:
            for line in f:

                line = re.sub(' +', ' ', line)
                if str(line).split(" ")[0] == "" and str(line).split(" ")[1] not in ['lo:', 'face']:
                    net_ifaces.append(str(line).split(" ")[1].split(':')[0])
                else:
                    pass
        f.close()
        return net_ifaces

    def get_mac_addr(self, net_iface_name):
        with open('/sys/class/net/%s/address' % net_iface_name) as f:
            mac = f.read()
        return mac

class GtpuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(GtpuController, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,{simple_switch_instance_name: self})
      
        self.ip_to_context = {}
        self.gtp_connections = {}
        self.GTPU_SWITCH_IP = None
        self.GTP_UDP_PORT = 2152

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default send to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.logger.info(ofproto.OFPP_CONTROLLER)
        self.logger.info(datapath.id)
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ARP requesting HW address of an IP assigned to a UE being managed by the switch
        # TODO: dynamic ARP management
        arp_pkt = pkt.get_protocol(arp.arp)
        if not self.GTPU_SWITCH_IP == None:
            if arp_pkt and arp_pkt.dst_ip == self.GTPU_SWITCH_IP:
                context = self.gtp_connections['172.0.0.30']
                self.handle_arp(datapath, 1, eth, arp_pkt, context.gw_tun_hw_addr)
            if arp_pkt and arp_pkt.dst_ip == '172.0.10.30':
                context = self.gtp_connections['172.0.10.30']
                self.handle_arp(datapath, 1, eth, arp_pkt, context.external_hw_src_addr)            
        elif arp_pkt.dst_ip in self.gtp_connections.keys():
            self.handle_arp(datapath, 1, eth, arp_pkt, context.external_hw_src_addr)

    # Handle the ARP
    def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp, eth_addr_to_reply):

        if pkt_arp.opcode == arp.ARP_REQUEST:
            self.logger.info("  [ARP] src: %s dst: %s INport:%s - mac_sent: %s", pkt_arp.src_ip, pkt_arp.dst_ip, port, eth_addr_to_reply)

            # Create ARP reply
            pkt = packet.Packet()
            address = datapath.address
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=eth_addr_to_reply))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=eth_addr_to_reply, src_ip=pkt_arp.dst_ip, dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip))
            self._send_packet(datapath, port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()

        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def configure_encapsulation(self, datapath, gtp_context):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        type_eth  = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_ETHERNET
        type_ip   = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
        type_udp   = (ofproto.OFPHTN_IP_PROTO << 16) | 17
        type_gtpu  = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152

        # Encap Flow
        match = parser.OFPMatch(in_port=2, eth_type=2048, ipv4_dst = gtp_context.ue_assigned_ip)
        actions = [
            parser.OFPActionDecap(type_eth, type_ip),
            parser.OFPActionEncap(type_gtpu),parser.OFPActionSetField(gtpu_flags=48),
            parser.OFPActionSetField(gtpu_teid=int(gtp_context.gtp_teid)),
            parser.OFPActionEncap(type_udp),parser.OFPActionSetField(udp_src=int(self.GTP_UDP_PORT)),
            parser.OFPActionSetField(udp_dst=int(self.GTP_UDP_PORT)),
            parser.OFPActionEncap(type_ip),
            parser.OFPActionSetField(ipv4_src=gtp_context.gw_tun_ip),
            parser.OFPActionSetField(ipv4_dst=gtp_context.enb_tun_ip),
            parser.OFPActionSetNwTtl(nw_ttl=64),
            parser.OFPActionEncap(type_eth),
            parser.OFPActionSetField(eth_src=gtp_context.gw_tun_hw_addr),
            parser.OFPActionSetField(eth_dst=gtp_context.enb_tun_hw_addr),
            parser.OFPActionOutput(1, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 2, match, actions)

    def configure_decapsulation(self, datapath, gtp_context):
        # Decap Flow
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        type_eth  = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_ETHERNET
        type_ip   = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
        type_udp   = (ofproto.OFPHTN_IP_PROTO << 16) | 17
        type_gtpu  = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152

        match = parser.OFPMatch(in_port=1,eth_type=2048,ipv4_src = gtp_context.enb_tun_ip,ip_proto=17,udp_dst=2152)
        actions = [
            parser.OFPActionDecap(type_eth, type_ip),
            parser.OFPActionDecap(type_ip, type_udp),
            parser.OFPActionDecap(type_udp, type_gtpu),
            parser.OFPActionDecap(type_gtpu, type_ip),
            parser.OFPActionEncap(type_eth),
            parser.OFPActionSetField(eth_src=gtp_context.external_hw_src_addr),
            parser.OFPActionSetField(eth_dst=gtp_context.external_hw_dst_addr),
            parser.OFPActionOutput(2, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

    # The incoming parameter is a decoded json
    def set_gtp_rules(self, configuration_values):
        # TODO: switch ID is not fixed
        print "  [INFO] Configuring GTP-U management"
        datapath = self.switches.get(1)

        # Store context related information
        self.gtp_connections[configuration_values['ue_ip']] = GtpuContextInformation(configuration_values)

        context = self.gtp_connections[configuration_values['ue_ip']]

        # We have to enable ARP management by setting this parameter
        self.GTPU_SWITCH_IP = context.gw_tun_ip
        #self.GTPU_SWITCH_ETH_ADDR = context.gw_tun_hw_addr

        # Configure decapsulation
        self.configure_decapsulation(datapath, context)

        # configure encapsulation
        self.configure_encapsulation(datapath, context)

        return configuration_values

# REST API interface exposed to Authentication side
class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @route('get', url+"{ue_ip}", methods=['GET'])
    def get_rules(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        print "  [INFO] Requesting data for %s IP" % kwargs['ue_ip']
        
        try:
            data = simple_switch.gtp_connections[kwargs['ue_ip']].to_json()
        except:
            data = json.dumps("{'status': 404, 'code': 'not-found', 'detail': 'No available rules for UE with IP %s'}" % kwargs['ue_ip'])
            return Response(status=404, body=data)

        return Response(status=200, content_type='application/json', body=data)

    @route('set', url , methods=['POST'])
    def add_rules(self, req, **kwargs):
        simple_switch = self.simple_switch_app

        reply = simple_switch.set_gtp_rules(req.json)

        #TODO: Errors management

        body = json.dumps(reply)
        return Response(status=200, content_type='application/json', body=body)

from os_ken.base import app_manager
from os_ken.controller import ofp_event, dpset
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import arp
from os_ken.lib.packet import lldp
from os_ken.lib.packet import ether_types
from os_ken.topology import switches
from os_ken.topology import api

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class Switch_Dict(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }
    def __init__(self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)
        # maybe you need a global data structure to save the mapping
        # just data structure in mission 1
        self.maps = {}
        # 在控制器级别的类生成树协议方法，防止环路
        self.dpset = kwargs['dpset']
        # 基于Kruskal算法构建生成树，并查集查询是否在树上
        self.preds = {}   
        # 记录开放的端口（边）
        self.open_port = {}
        self.open_links = {}

        

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    # 并查集查公共祖先
    def get_pred(self, switch):
        return switch if self.preds[switch] is None else self.get_pred(self.preds[switch])

    # 新加入交换机时触发事件
    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def dp_event_handler(self, ev):
        dp = ev.dp
        ports = ev.ports
        enter = ev.enter
        if not enter:
            self.discover()
            return
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.preds[dp.id] = None
        self.open_port[dp.id] = set()
        # 遍历每个端口，让交换机发送lldp（链路层发现协议）
        for port in ports:
            # 跳过大于最大物理端口限制的特殊端口
            if port.port_no > ofp.OFPP_MAX:
                continue
            if port.state == ofp.OFPPS_LIVE :
                self.open_port[dp.id].add(port.port_no)
            eth = ethernet.ethernet(dst='01:80:c2:00:00:0e', # lldp协议默认 
                                src=port.hw_addr,
                                ethertype=ether_types.ETH_TYPE_LLDP)    # 标记ethertype，后续进行特判
            # 构造lldp协议的tlv（参照os_ken reference， ChassisID，PortID，TTL，End四项必须设置）
            # ChassisID用于用于存储交换机ID
            cid = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(dp.id).encode('utf-8'))
            # portid用于存储发出端口
            portid = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port.port_no).encode('utf-8'))
            # 生存时间
            ttl = lldp.TTL(ttl=32)
            # end
            end = lldp.End()
            # 构造lldp协议
            lld = lldp.lldp(tlvs=[cid, portid, ttl, end])
            
            # 构造数据包
            pkt = packet.Packet()
            pkt.add_protocol(eth)
            pkt.add_protocol(lld)
            pkt.serialize()

            # 设置action，发给对应端口
            actions = [parser.OFPActionOutput(port.port_no)]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,actions=actions, data=pkt.data)
            dp.send_msg(out)
    
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_event_handler(self, ev):
        self.discover()
    
    # 遍历每个交换机，重新进行链路层的发现。
    def discover(self):
        self.open_links = {}
        for dpid, dp in self.dpset.get_all():
            self.preds[dpid] = None
            self.open_port[dpid] = set()
            self.maps[dpid] = {}
            ports = self.dpset.get_ports(dp.id)
            ofp = dp.ofproto
            for port in ports:
                # 跳过大于最大物理端口限制的特殊端口
                if port.port_no > ofp.OFPP_MAX:
                    continue
                if port.state == ofp.OFPPS_LIVE :
                    self.open_port[dp.id].add(port.port_no)
        for dpid, dp in self.dpset.get_all():
            ports = self.dpset.get_ports(dp.id)
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            # 遍历每个端口，让交换机发送lldp（链路层发现协议）
            for port in ports:
                # 跳过大于最大物理端口限制的特殊端口
                if port.port_no > ofp.OFPP_MAX:
                    continue
                eth = ethernet.ethernet(dst='01:80:c2:00:00:0e', # lldp协议默认 
                                    src=port.hw_addr,
                                    ethertype=ether_types.ETH_TYPE_LLDP)    # 标记ethertype，后续进行特判
                # 构造lldp协议的tlv（参照os_ken reference， ChassisID，PortID，TTL，End四项必须设置）
                # ChassisID用于用于存储交换机ID
                cid = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(dp.id).encode('utf-8'))
                # portid用于存储发出端口
                portid = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port.port_no).encode('utf-8'))
                # 生存时间
                ttl = lldp.TTL(ttl=32)
                # end
                end = lldp.End()
                # 构造lldp协议
                lld = lldp.lldp(tlvs=[cid, portid, ttl, end])
                
                # 构造数据包
                pkt = packet.Packet()
                pkt.add_protocol(eth)
                pkt.add_protocol(lld)
                pkt.serialize()

                # 设置action，发给对应端口
                actions = [parser.OFPActionOutput(port.port_no)]
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,actions=actions, data=pkt.data)
                dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id
        # the port that receive the packet
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # 对之前发送的LLDP进行判定
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            # 解码发送者的交换机ID和发送端口
            cid = int(lldp_pkt.tlvs[0].chassis_id.decode('utf-8'))
            port = int(lldp_pkt.tlvs[1].port_id.decode('utf-8'))
            
            # 查询是否在同一颗树，若不在，则合并到一起，并设置加入开放链路列表，否则，将端口标记为关闭。
            # 如果目前链路已经为开放状态，则不必进行检查。
            if (cid, dpid) in self.open_links or (dpid, cid) in self.open_links:
                return
            if self.get_pred(cid) != self.get_pred(dpid):
                print(f"{cid} {dpid}")
                self.preds[self.get_pred(dpid)] = cid
                self.open_links[(cid, dpid)] = (port, in_port)
            else:
                print(f"{cid} {dpid} {self.open_port}")
                self.open_port[cid].discard(port)
                self.open_port[dpid].discard(in_port)
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        print(self.open_port)
        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src
        # get protocols
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if dst == ETHERNET_MULTICAST and ARP in header_list:
            pass

        # you need to code here to avoid broadcast loop to finish mission 2
        
        # self-learning
        # you need to code here to avoid the direct flooding
        # having fun
        # :)
        # just code in mission 1
        # 如果是新交换机，为这个交换机新开一个映射表
        
        if not dpid in self.maps:
            self.maps[dpid] = {}
        # 学习映射
        self.maps[dpid][src] = in_port
        if not dst in self.maps[dpid]:  # 如果未学习，则向目前开启的端口发数据包
            actions = [] 
            for i in self.open_port[dpid]:
                if i != in_port:
                    actions.append(parser.OFPActionOutput(i))
            if len(actions) == 0:
                return
        else:
            actions = [parser.OFPActionOutput(self.maps[dpid][dst])]   # 如果已学习，则向指定端⼝转发数据包 
            match = parser.OFPMatch(eth_dst=dst)  
            self.add_flow(dp, 1, match, actions, idle_timeout=2, hard_timeout=10)
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],actions=actions, data=msg.data)
        dp.send_msg(out)
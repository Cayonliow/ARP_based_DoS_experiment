from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event, controller
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

class Flag(object):
    mac_to_add=0
    #place = 47

class monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_to_meter = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        #self.record_req_res = {}
        self.record_req_res = {}
        self.been_initialized = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Flow entry added: all unknown packets are packetIn to controller")


        match1 = parser.OFPMatch(eth_type = 0x0806,arp_op = 1)
        actions1 = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 3, match1, actions1)
        self.logger.info("Flow entry added: all ARP request packets are passed through this and being counted")

        match2 = parser.OFPMatch(eth_type = 0x0806, arp_op = 2)
        actions2 = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 3, match2, actions2)
        self.logger.info("Flow entry added: all ARP response packets are passed through this and being counted")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        datapath_id = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if pkt.get_protocol(arp.arp) and self.record_req_res['marked'] == 'yes':
            self.logger.info("Condition entering: ARP packets are packetIn to the controller")
            pkt_arp = pkt.get_protocol(arp.arp)
            arp_src_mac = pkt_arp.src_mac
            arp_dst_mac = pkt_arp.dst_mac
            self.logger.info("Source MAC address = %s Destination MAC address = %s",arp_src_mac, arp_dst_mac )
            self.logger.info("Recodring Destination MAC address")

            int_src_mac = int(arp_src_mac.translate(None, ":.- "), 16)
            self.logger.info('Source mac in strings = %s',arp_src_mac)
            self.logger.info('Source mac in integer = %s',int_src_mac)
            print "Source mac in integer = ","{0:b}".format(int_src_mac)

            str_bin_mac = str("{0:b}".format(self.record_req_res['mac_to_check'] & int_src_mac))
            print "binary to compare     = " ,"{0:b}".format(self.record_req_res['mac_to_check'])
            
            self.logger.info('after compare          = %s',str_bin_mac)
            while len(str_bin_mac)<48:
                str_bin_mac = '0'+str_bin_mac
            self.logger.info('after compare          = %s',str_bin_mac)

            self.logger.info('self.record_req_res[bfs_place] = %d\n',self.record_req_res['bfs_place'])
            
            if str_bin_mac[self.record_req_res['bfs_place']] == '0':
                self.record_req_res['mac_to_check'] = self.record_req_res['mac_to_check'] - (1 << (47 - self.record_req_res['bfs_place']))
                
            if self.record_req_res['bfs_place']< 47:
                self.record_req_res['mac_to_check'] = self.record_req_res['mac_to_check'] + (1 << (46 - self.record_req_res['bfs_place']))

            print "after checking 1      = " ,"{0:b}".format(self.record_req_res['mac_to_check'])
            checking1_str = str("{0:b}".format(self.record_req_res['mac_to_check']))
            while len(checking1_str)<48:
                checking1_str = '0' + checking1_str
            self.logger.info("after checking 1string= %s",checking1_str)

            self.record_req_res['bfs_place'] = self.record_req_res['bfs_place'] + 1 

            if self.record_req_res['bfs_place'] == 48:
                k=str(hex(self.record_req_res['mac_to_check']))
                k = k[2:]

                while len(k)<12:
                    k = '0' + k

                k_mac = k[0:2]+":"+k[2:4]+":"+k[4:6]+":"+k[6:8]+":"+k[8:10]+":"+k[10:12]

                match = parser.OFPMatch(eth_src=k_mac)
                actions = None
                self.add_flow(datapath,7,match, actions)

                self.logger.info('BFS done, spoofing mac address = %s', k_mac)
                self.logger.info('the bad guy is being blocked')
                self.logger.info("Flow entry added: all packets from the spoofer are blocked")

                self.record_req_res['marked'] = 'yes'
                self.record_req_res['bfs_place'] = 0
                self.record_req_res['mac_to_check'] = 1 << 47

                match = parser.OFPMatch(eth_type = 0x0806, arp_op = 1)    
                self.remove_flows(datapath,match,6)
                self.logger.info("Flow entry removed: Stop blocking all ARP request ")

                match1 = parser.OFPMatch(eth_type = 0x0806,arp_op = 1)
                actions1 = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                self.remove_flows(datapath, match1, 3)
                self.add_flow(datapath, 3, match1, actions1)
                self.logger.info("Flow entry reset: all ARP request packets are passed through this and being counted")

                match2 = parser.OFPMatch(eth_type = 0x0806, arp_op = 2)
                actions2 = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.remove_flows(datapath, match2, 3)
                self.add_flow(datapath, 3, match2, actions2)
                self.logger.info("Flow entry reset: all ARP response packets are passed through this and being counted")

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

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofproto.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofproto.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.info('OFPFlowRemoved received: '
                        'cookie=%d priority=%d reason=%s table_id=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'idle_timeout=%d hard_timeout=%d '
                        'packet_count=%d byte_count=%d match.fields=%s',
                        msg.cookie, msg.priority, reason, msg.table_id,
                        msg.duration_sec, msg.duration_nsec,
                        msg.idle_timeout, msg.hard_timeout,
                        msg.packet_count, msg.byte_count, msg.match)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        para = 1
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)

            self.logger.info("Monitoring every %d second",para)
            hub.sleep(para)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        msg = ev.msg
        datapath = msg.datapath
        datapath_id = datapath.id
        
        self.logger.info(" ")
        self.logger.info(" ")
        self.logger.info('arp_op  packets  bytes  priority')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 3],
                           key=lambda flow: ()):
            self.logger.info('%6x %8d %5d %8d %8s',
                             stat.match['arp_op'],
                             stat.packet_count, stat.byte_count, stat.priority, datapath_id)

            if(self.record_req_res.has_key('datapath')):
                self.been_initialized = True
            else:
                self.been_initialized = False
    
            if self.been_initialized == False:
                    self.record_req_res = {'datapath': datapath_id, 'req': 0, 'res': 0, 'marked': 'no', 'bfs_place': 0, 'mac_to_block': 1 << 47}


            if stat.match['arp_op'] == 1:
                if(self.record_req_res['datapath'] == datapath_id):
                    self.record_req_res['req'] = stat.packet_count
            
            if stat.match['arp_op'] == 2:
                self.logger.info('Have ARP response')
                if(self.record_req_res['datapath'] == datapath_id):
                    self.record_req_res['res'] = stat.packet_count

            self.logger.info('Checking threshold value\n\n\n')
            threshold_v = self.record_req_res['res'] - self.record_req_res['req']
        
            if flow.priority == 3:
                self.logger.info('arp_req = %d arp_res = %d diff, m = %d',self.record_req_res['req'] - record_req_res['res'], threshold_v)

            if threshold_v > 3 and self.record_req_res['marked'] == 'no' :
                self.logger.info("Condition entering: Suspicious condition and clear the recording table")
                self.record_req_res['req'] = 0
                self.record_req_res['res'] = 0
                self.record_req_res['marked'] = 'yes'
                self.record_req_res['bfs_place'] = 0
                self.record_req_res['mac_to_check'] = 1 << 47

                self.bfs_add_flow(6, datapath.id)


        self.logger.info(" ")
        self.logger.info(" ")
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')        
 
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')

        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d %d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count, int(stat.match['eth_src'].translate(None, ":.- "), 16))

        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
 # suspicous       
    def bfs_add_flow(self, num, datapath_id):
        self.logger.info("Condition entering: bfs_add_flow, first block")
        datapath = self.datapaths[datapath_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type = 0x0806, arp_op = 1)
        actions = None
        self.add_flow(datapath,6,match, actions)
        self.logger.info("Flow entry added: all ARP request from the target destination are blocked")

        match = parser.OFPMatch(eth_type = 0x0806, arp_op = 2)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]        
        self.add_flow(datapath,5,match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if actions == None:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,[])]
        else:   
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,flags=ofproto.OFPFF_SEND_FLOW_REM,hard_timeout=hard_timeout)
                                    
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,flags=ofproto.OFPFF_SEND_FLOW_REM, hard_timeout=hard_timeout)

        datapath.send_msg(mod)

    def remove_flows(self, datapath, match ,priority):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath,
                                                      command = ofproto.OFPFC_DELETE,                                                      priority=10,
                                                      buffer_id = ofproto.OFPCML_NO_BUFFER,
                                                      out_port = ofproto.OFPP_ANY,
                                                      out_group = ofproto.OFPG_ANY, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                                      match = match, instructions = inst)

        datapath.send_msg(mod)

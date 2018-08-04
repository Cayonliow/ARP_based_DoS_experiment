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
#from ryu.controller import dpset

class Flag(object):
    i = 3
    time_b = False
    arp_req = 0
    arp_res = 0

class monitor1(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(monitor1, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_to_meter = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.time_b_record_mac = []
        self.dst_mac_block_arp_res=[]
        self.record_req_res = []
        self.list = []
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
        _arp = pkt.get_protocol(arp.arp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # time-based
        _marked=False
        for elem in self.record_req_res:
            if(elem['datapath'] == datapath_id):
                if elem['marked'] == 'yes':
                    _marked=True
        if _arp:
            self.logger.info('\n\n\nmsg.match[eth_src] = %s\n\n\n',_arp.src_mac)

        if _arp and _arp.src_mac in self.dst_mac_block_arp_res:
            self.logger.info("Condition entering: Destination start sending out ARP request")
            src_mac = _arp.src_mac
            match = parser.OFPMatch(eth_dst = src_mac, eth_type = 0x0806, arp_op = 2)
            self.remove_flows(datapath, match, 8)
            for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id and elem['marked']=='no'):
                        elem['req']=0
                        elem['res']=0
                        elem['marked']='no'
            self.logger.info("Flow entry removed: The host can start receiving ARP response")         

            match = parser.OFPMatch(eth_type = 0x0806, eth_src = src_mac, arp_op=1)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
            self.remove_flows(datapath, match, 9)
            self.logger.info("Flow entry removed: ARP request wouldnt be paccketIn to the controller")

            for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id and elem['marked']=='yes'):
                        elem['req']=0
                        elem['res']=0
                        elem['marked']='no'



        elif _arp and _marked == True:
            self.logger.info("Condition entering: ARP packets are packetIn to the controller")
            pkt_arp = pkt.get_protocol(arp.arp)
            arp_src_mac = pkt_arp.src_mac
            arp_dst_mac = pkt_arp.dst_mac
            self.logger.info("Source MAC address = %s Destination MAC address = %s",arp_src_mac, arp_dst_mac )
            self.logger.info("Recodring Destination MAC address")

            been_ini = False
            for elem in self.time_b_record_mac:
                if(elem['datapath'] == datapath_id and elem['arp_dst_mac'] == arp_dst_mac):
                    been_ini = True
                    break

            if been_ini == False:
                self.time_b_record_mac.append({'datapath': datapath_id, 'arp_dst_mac': arp_dst_mac, 'counting':0 })
                self.logger.info("Initialized: time_b_record_mac[%s][%s]",datapath_id, arp_dst_mac)

            for elem in self.time_b_record_mac:
                if(elem['datapath'] == datapath_id and elem['arp_dst_mac'] == arp_dst_mac):
                    elem['counting'] = elem['counting'] + 1
                    self.logger.info("Showing: time_b_record_mac[%s][%s] = %d",datapath_id, arp_dst_mac, elem['counting'])
                    break

             
            self.logger.info(" ")
            self.logger.info(" ")
            self.logger.info("datapath  | arp_dst_mac     | Amount")
            self.logger.info("----------|-----------------|----------")

            for elem in self.time_b_record_mac:
                self.logger.info("%9s|%17s|%3d",elem['datapath'], elem['arp_dst_mac'], elem['counting'])

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
        datapath_id = datapath.id
        
        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
            self.logger.info("HARD TIMEOUT: Start settling up the count")
            self.logger.info("Record is cleared")

            _index = 0
            dst_mac_to_block = 'none'

            for elem in self.time_b_record_mac:
                if elem['datapath'] == datapath_id:
                    if elem['counting'] > _index:
                        _index = elem['counting']

            if (_index>1):
                self.logger.info("Confirmed: really being attacked")

                for elem in self.time_b_record_mac:
                    if elem['datapath'] == datapath_id and elem['counting'] == _index:
                        dst_mac_to_block = elem['arp_dst_mac']
                        break

                match1 = parser.OFPMatch(eth_type = 0x0806,arp_op = 1)
                actions1 = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                self.remove_flows(datapath, match1, 3)
                self.add_flow(datapath, 3, match1, actions1)
                self.logger.info("Flow entry reset: all ARP request packets are passed through this and being counted")

                match2 = parser.OFPMatch(eth_type = 0x0806, arp_op = 2)
                actions2 = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.remove_flows(datapath, match2, 3)
                self.add_flow(datapath, 3, match2, actions2)
                for elem in self.time_b_record_mac:
                    if elem['datapath'] == datapath_id and elem['arp_dst_mac'] == dst_mac_to_block:
                        elem['counting'] = 0
                        break
                self.logger.info("Flow entry reset: all ARP response packets are passed through this and being counted")

                self.dst_mac_block_arp_res.append(dst_mac_to_block)
                for mac in self.dst_mac_block_arp_res:
                    self.logger.info("dst_mac_block_arp_res %s", mac)

                match = parser.OFPMatch(eth_type = 0x0806, eth_dst = dst_mac_to_block, arp_op=2)
                actions = None
                self.add_flow(datapath, 8, match, actions)
                self.logger.info("Flow entry added: All ARP response packets sending to this host are dropped")

                match = parser.OFPMatch(eth_type = 0x0806, eth_src = dst_mac_to_block, arp_op=1)
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath, 9, match, actions)
                self.logger.info("Flow entry added: ARP request from the host would packetIn to the controller")


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
            self.logger.info('%6d %8d %5d %8d %8s',
                             stat.match['arp_op'],
                             stat.packet_count, stat.byte_count, stat.priority, datapath_id)

            if stat.match['arp_op'] == 1: 
                for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id):
                        self.been_initialized = True
                        break
                    else:
                        self.been_initialized = False

                if self.been_initialized == False:
                    self.record_req_res.append({'datapath': datapath_id, 'req': 0, 'res': 0, 'marked': 'no'})

                for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id):
                        elem['req'] = stat.packet_count
            
            if stat.match['arp_op'] == 2:
                for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id):
                        self.been_initialized = True
                        break
                    else:
                        self.been_initialized = False

                if self.been_initialized == False:
                    self.record_req_res.append({'datapath': datapath_id, 'req': 0, 'res': 0, 'marked': 'no'})

                for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id):
                        elem['res'] = stat.packet_count

            for elem in self.record_req_res:
                if(elem['datapath'] == datapath_id):
                    threshold_v = elem['res']-elem['req']
                    self.logger.info("threshold(%d) = ['res'](%d) - ['req'](%d)",threshold_v,elem['res'], elem['req'])
        
            if flow.priority == 3:
                self.logger.info('arp_req = %d arp_res = %d diff, m = %d',self.record_req_res[datapath_id][req] - record_req_res[datapath_id][res], threshold_v)

            if threshold_v > 3:
                for elem in self.record_req_res:
                    if(elem['datapath'] == datapath_id and elem['marked']=='no'):
                        elem['req']=0
                        elem['res']=0
                        elem['marked']='yes'
                        self.time_based_packetin(6, datapath.id)

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
    def time_based_packetin(self, num, datapath_id):
        self.logger.info("Condition entering: time_based_packetin, all ARP response are packetIn")
        datapath = self.datapaths[datapath_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #match = parser.OFPMatch()
        match = parser.OFPMatch(eth_type = 0x0806, arp_op = 2)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]        
        self.add_flow(datapath,5,match, actions,None, num)



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

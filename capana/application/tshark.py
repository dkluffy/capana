# -*- coding: utf-8 -*-
import subprocess
import json

from capana.application.base import BackEnd
from capana.application.tsharkutil import get_process_path
from capana.application.base import BackEndError



class Tshark(BackEnd):
    def __init__(self,data_source,filters=None):
        self._path = get_process_path()
        self.data_source = data_source
        self.filters = filters

    def table(self,tablename,columns=None):
        return self._run_t_func(tablename)

    def _decode_to_json(self,layers,strict=False):
        """
        layers: string list ['tcp.port','tcp.payload']
            tcp
            tcp.port
            tcp.payload
            tcp.stream
            
            ip.addr
            ipv6.addr

            udp
            udp.port
            udp.payload
            udp.stream

        temp_json:
            {'_index': 'packets-2021-03-17',
                '_type': 'doc',
                '_score': None,
                '_source': {'layers': {}}}
        """
        dash_e = [ '-e' ]*len(layers)*2
        for e in range(1,len(dash_e),2):
            dash_e[e] = layers[int(e/2)] 
        
        args = ['-Y',self.filters,'-q','-T','json' ] + dash_e
        if self.filters is None or self.filters=="":
            args = args[2:]
        
        temp_json = json.loads(self._run(args))
        
        #drop ,if strict
        #TODO: 优化
        if strict:
            ret = []
            for tmpj in temp_json:
                keys = tmpj["_source"]["layers"].keys()
                if len(keys) == len(layers):
                    ret.append(tmpj)
            return ret
        return temp_json

    def _conv(self,proto):
        """
        filters can be: ip.addr == <ip>; -Y will not work

        proto：
            ip
            ipv6
            tcp
            udp

        """
        conv_strs = ['conv',proto,self.filters]
        if self.filters is None or self.filters == "":
            conv_strs = conv_strs[:-1]
        args = ['-q','-z',",".join(conv_strs)]
        return self._convert_conv_table(self._run(args))

    #TODO:改成装饰函数
    #@staticmethod
    # def _convert_conv_table(src):
    #     """
    #     src:

    #     ================================================================================
    #     IPv4 Conversations
    #     Filter:ip.addr==192.168.2.147
    #                                                    |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
    #                                                    | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
    #     192.168.2.147        <-> 192.168.2.255              0 0bytes         10 2,294bytes      10 2,294bytes     8.149062000        49.9288
    #     ================================================================================

    #     return:
    #         [dict,]
    #     """
    #     tab = [ r.split("\n") for r in src.split("\n")[5:-2] ]
    #     cols = ['src',
    #             'sig1',
    #             'dst',
    #             'frames_to_src',
    #             'bytes_to_src',
    #             'frames_to_dst',
    #             'bytes_to_dst',
    #             'frame_total',
    #             'bytes_total',
    #             'sec_relative',
    #             'sec_duration']
    #     return [ row_to_dict(r[0].split(),cols) for r in tab ]
    
    def _endpoints(self,proto):
        """
        filters can be: ip.addr == <ip>; -Y will not work

        proto：
            ip
            ipv6
            tcp
            udp

        """
        conv_strs = ['endpoints',proto,self.filters]
        args = ['-q','-z',",".join(conv_strs)]
        return self._convert_endpoits_table(self._run(args))

    # @staticmethod
    # def _convert_endpoits_table(src):
    #     """
    #     src:

    #     tshark -r a.pcapng -q -z endpoints,ip,ip.addr==192.168.2.155
    #     1 ================================================================================
    #     2 IPv4 Endpoints
    #     3 Filter:ip.addr==192.168.2.155
    #     4                        |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
    #     192.168.2.155                  1           243          1             243           0               0
    #     192.168.2.255                  1           243          0               0           1             243
    #     ==============================================================================================================================================================
        
    #     return:
    #         [j{},]
    #     """
    #     tab = [ r.split("\n") for r in src.split("\n")[4:-2] ]
    #     cols = ['endpoint',
    #             'packets',
    #             'bytes',
    #             'tx_packets',
    #             'tx_bytes',
    #             'rx_packets',
    #             'rx_bytes']
    #     return [ row_to_dict(r,cols) for r in tab ]
        

    def _run(self,args):
        params = [self._path,'-n','-r',self.data_source] + args
        p = subprocess.Popen(params, bufsize=-1,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        r,err = p.communicate()
        if err != b'':
            raise BackEndError("tshark error:" + bytes.decode(err))

        return bytes.decode(r)

    def t_func_tcpv4_payload(self):
        layers = ["tcp.payload","ip.addr","tcp.port","tcp.stream"]
        return self._decode_to_json(layers,True)
    
    def t_func_udpv4_payload(self):
        layers = ["udp.payload","ip.addr","udp.port","udp.stream"]
        return self._decode_to_json(layers,True)
    
    def t_func_tcpv6_payload(self):
        layers = ["tcp.payload","ipv6.addr","tcp.port","tcp.stream"]
        return self._decode_to_json(layers,True)

    def t_func_udpv6_payload(self):
        layers = ["udp.payload","ipv6.addr","udp.port","udp.stream"]
        return self._decode_to_json(layers,True)
        
        
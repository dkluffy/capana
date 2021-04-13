# -*- coding: utf-8 -*-
import subprocess
import json

from capana.application.base import BackEnd
from capana.application.tsharkutil import get_process_path
from capana.application.base import BackEndError

from capana.application.converts import convert
import capana.application.converts as table_type

class Tshark(BackEnd):
    def __init__(self,data_source,filters=None):
        self._path = get_process_path()
        self.data_source = data_source
        self.filters = filters

    def table(self,tablename,columns=None):
        """
        封装调用 Tshark.t_func_*
        """
        return self._run_t_func(tablename)

    def _decode_to_json(self,layers,strict=False):
        """
        直接把数据包转换为JSON格式，layers控制需要包含的字段
        
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

    def get_payload_by_stream(self,stream_id: int):
        """
        extra payload  from output of _decode_to_json
        """
        pass

    def get_payload_by_conv(self,conv_ips:list):
        """
        extra payload  from output of _decode_to_json
        """
        pass

    @convert
    def _conv(self,proto,format=table_type.conv_table):
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
        return self._run(args)

    #第二种用法，同@convert,但是不能在 调用_endpoints时控制输出的
    #@table_wrapper(table_type=table_type.endpoits_table)
    @convert
    def _endpoints(self,proto,format=table_type.endpoits_table):
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
        return self._run(args)

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
        
        